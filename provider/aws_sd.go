/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package provider

import (
	"strings"

	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	sd "github.com/aws/aws-sdk-go/service/servicediscovery"
	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/pkg/apis/externaldns"
	"github.com/kubernetes-incubator/external-dns/plan"
	"github.com/linki/instrumented_http"
	log "github.com/sirupsen/logrus"
	"reflect"
)

const (
	sdElbHostnameSuffix  = ".elb.amazonaws.com"
	sdDefaultRecordTTL   = 300
	sdServiceDescription = "Managed by Kubernetes External DNS (<owner-id>)"
)

// AWSServiceDiscoveryAPI is the subset of the AWS Route53 Auto Naming API that we actually use. Add methods as required.
// Signatures must match exactly. Taken from https://github.com/aws/aws-sdk-go/blob/master/service/servicediscovery/api.go
type AWSServiceDiscoveryAPI interface {
	CreateService(input *sd.CreateServiceInput) (*sd.CreateServiceOutput, error)
	DeregisterInstance(input *sd.DeregisterInstanceInput) (*sd.DeregisterInstanceOutput, error)
	GetService(input *sd.GetServiceInput) (*sd.GetServiceOutput, error)
	ListInstancesPages(input *sd.ListInstancesInput, fn func(*sd.ListInstancesOutput, bool) bool) error
	ListNamespacesPages(input *sd.ListNamespacesInput, fn func(*sd.ListNamespacesOutput, bool) bool) error
	ListServicesPages(input *sd.ListServicesInput, fn func(*sd.ListServicesOutput, bool) bool) error
	RegisterInstance(input *sd.RegisterInstanceInput) (*sd.RegisterInstanceOutput, error)
	UpdateService(input *sd.UpdateServiceInput) (*sd.UpdateServiceOutput, error)
}

// AWSSDProvider is an implementation of Provider for AWS Route53 Auto Naming.
type AWSSDProvider struct {
	client AWSServiceDiscoveryAPI
	dryRun bool
	// only consider namespaces ending in this suffix
	namespaceFilter DomainFilter
	// filter namespace by type (private or public)
	namespaceTypeFilter *sd.NamespaceFilter
	// refers to the owner id of the managed services
	ownerID string
}

// NewAWSProvider initializes a new AWS Route53 Auto Naming based Provider.
func NewAWSSDProvider(domainFilter DomainFilter, namespaceTypeFilter NamespaceTypeFilter, ownerId string, dryRun bool) (*AWSSDProvider, error) {
	config := aws.NewConfig()

	config = config.WithHTTPClient(
		instrumented_http.NewClient(config.HTTPClient, &instrumented_http.Callbacks{
			PathProcessor: func(path string) string {
				parts := strings.Split(path, "/")
				return parts[len(parts)-1]
			},
		}),
	)

	sess, err := session.NewSessionWithOptions(session.Options{
		Config:            *config,
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}
	sess.Handlers.Build.PushBack(request.MakeAddToUserAgentHandler("ExternalDNS", externaldns.Version))

	provider := &AWSSDProvider{
		client:              sd.New(sess),
		namespaceFilter:     domainFilter,
		namespaceTypeFilter: namespaceTypeFilter.toAwsApiRequestFilter(),
		dryRun:              dryRun,
		ownerID:             ownerId,
	}

	return provider, nil
}

func (p *AWSSDProvider) Records() (endpoints []*endpoint.Endpoint, err error) {
	namespaces, err := p.ListNamespaces()
	if err != nil {
		return nil, err
	}

	for _, ns := range namespaces {
		services, err := p.ListServicesByNamespaceId(ns.Id)
		if err != nil {
			return nil, err
		}

		for _, srv := range services {
			instances, err := p.ListInstancesByServiceId(srv.Id)
			if err != nil {
				return nil, err
			}

			if len(instances) > 0 {
				// DNS name of the record is a concatenation of service and namespace
				dnsName := *srv.Name + "." + *ns.Name
				ep, err := p.instancesToEndpoint(dnsName, srv, instances)
				if err != nil {
					return nil, err
				}
				endpoints = append(endpoints, ep)
			}
		}
	}

	return endpoints, nil
}

func (p *AWSSDProvider) instancesToEndpoint(recordName string, srv *sd.Service, instances []*sd.InstanceSummary) (*endpoint.Endpoint, error) {
	newEndpoint := &endpoint.Endpoint{
		DNSName:   recordName,
		RecordTTL: endpoint.TTL(aws.Int64Value(srv.DnsConfig.DnsRecords[0].TTL)),
		Targets:   make(endpoint.Targets, 0, len(instances)),
	}

	for _, inst := range instances {
		// CNAME
		if inst.Attributes["AWS_INSTANCE_CNAME"] != nil && aws.StringValue(srv.DnsConfig.DnsRecords[0].Type) == sd.RecordTypeCname {
			newEndpoint.RecordType = endpoint.RecordTypeCNAME
			newEndpoint.Targets = append(newEndpoint.Targets, aws.StringValue(inst.Attributes["AWS_INSTANCE_CNAME"]))

			// ALIAS
		} else if inst.Attributes["AWS_ALIAS_DNS_NAME"] != nil {
			newEndpoint.RecordType = endpoint.RecordTypeCNAME
			newEndpoint.Targets = append(newEndpoint.Targets, aws.StringValue(inst.Attributes["AWS_ALIAS_DNS_NAME"]))

			// IP-based target
		} else if inst.Attributes["AWS_INSTANCE_IPV4"] != nil {
			newEndpoint.RecordType = endpoint.RecordTypeA
			newEndpoint.Targets = append(newEndpoint.Targets, aws.StringValue(inst.Attributes["AWS_INSTANCE_IPV4"]))
		} else {
			return nil, fmt.Errorf("FATAL ERROR: Instance not valid \"%v\"", inst)
		}
	}

	return newEndpoint, nil
}

func (p *AWSSDProvider) ApplyChanges(changes *plan.Changes) error {
	// return early if there is nothing to change
	if len(changes.Create) == 0 && len(changes.Delete) == 0 && len(changes.UpdateNew) == 0 {
		log.Info("All records are already up to date")
		return nil
	}

	// convert updates to delete and create operation if applicable (updates not supported)
	creates, deletes := p.updatesToCreates(changes)
	changes.Delete = append(changes.Delete, deletes...)
	changes.Create = append(changes.Create, creates...)

	namespaces, err := p.ListNamespaces()
	if err != nil {
		return err
	}

	err = p.submitDeletes(namespaces, changes.Delete)
	if err != nil {
		return err
	}

	err = p.submitCreates(namespaces, changes.Create)
	if err != nil {
		return err
	}

	return nil
}

func (p *AWSSDProvider) updatesToCreates(changes *plan.Changes) (creates []*endpoint.Endpoint, deletes []*endpoint.Endpoint) {
	for i, old := range changes.UpdateOld {
		current := changes.UpdateNew[i]

		if !reflect.DeepEqual(old.Targets, current.Targets) || old.DNSName != current.DNSName {
			// when targets or DNS name differ the old instances need to be de-registered first
			deletes = append(deletes, old)
		}

		// always register (or re-register) instance with the current data
		creates = append(creates, current)
	}

	return creates, deletes
}

func (p *AWSSDProvider) submitCreates(namespaces []*sd.NamespaceSummary, changes []*endpoint.Endpoint) error {
	changesByNamespaceId := p.changesByNamespaceId(namespaces, changes)

	for nsId, changeList := range changesByNamespaceId {
		services, err := p.ListServicesByNamespaceId(aws.String(nsId))
		if err != nil {
			return err
		}

		for _, ch := range changeList {
			_, srvName := p.parseHostname(ch.DNSName)

			srv := services[srvName]
			summary := serviceToServiceSummary(srv)
			if srv == nil {
				// when service is missing create a new one
				summary, err = p.CreateService(&nsId, &srvName, ch)
				if err != nil {
					return err
				}
				// update local list of services
				services, err = p.ListServicesByNamespaceId(aws.String(nsId))
				if err != nil {
					return err
				}
			} else {
				// update service TTL when differs
				if ch.RecordTTL.IsConfigured() && *srv.DnsConfig.DnsRecords[0].TTL != int64(ch.RecordTTL) {
					err := p.UpdateService(srv, ch)
					if err != nil {
						return err
					}
				}
			}

			err = p.RegisterInstance(summary, ch)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *AWSSDProvider) submitDeletes(namespaces []*sd.NamespaceSummary, changes []*endpoint.Endpoint) error {
	changesByNamespaceId := p.changesByNamespaceId(namespaces, changes)

	for nsId, changeList := range changesByNamespaceId {
		services, err := p.ListServicesByNamespaceId(aws.String(nsId))
		if err != nil {
			return err
		}

		for _, ch := range changeList {
			hostname := ch.DNSName
			_, srvName := p.parseHostname(hostname)

			srv := serviceToServiceSummary(services[srvName])
			if srv == nil {
				return fmt.Errorf("FATAL ERROR: Service \"%s\" is missing", srvName)
			}

			err := p.DeregisterInstance(srv, ch)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *AWSSDProvider) ListNamespaces() ([]*sd.NamespaceSummary, error) {
	namespaces := make([]*sd.NamespaceSummary, 0)

	f := func(resp *sd.ListNamespacesOutput, lastPage bool) bool {
		for _, ns := range resp.Namespaces {
			if !p.namespaceFilter.Match(aws.StringValue(ns.Name)) {
				continue
			}
			namespaces = append(namespaces, ns)
		}

		return true
	}

	err := p.client.ListNamespacesPages(&sd.ListNamespacesInput{
		Filters: []*sd.NamespaceFilter{p.namespaceTypeFilter},
	}, f)
	if err != nil {
		return nil, err
	}

	return namespaces, nil
}

// returns map[srv_name]*sd.Service
func (p *AWSSDProvider) ListServicesByNamespaceId(namespaceId *string) (map[string]*sd.Service, error) {
	serviceIds := make([]*string, 0)

	f := func(resp *sd.ListServicesOutput, lastPage bool) bool {
		for _, srv := range resp.Services {
			serviceIds = append(serviceIds, srv.Id)
		}

		return true
	}

	err := p.client.ListServicesPages(&sd.ListServicesInput{
		Filters: []*sd.ServiceFilter{{
			Name:   aws.String(sd.ServiceFilterNameNamespaceId),
			Values: []*string{namespaceId},
		}},
	}, f)
	if err != nil {
		return nil, err
	}

	// get detail of each listed service
	services := make(map[string]*sd.Service)
	for _, serviceId := range serviceIds {
		output, err := p.client.GetService(&sd.GetServiceInput{
			Id: serviceId,
		})
		if err != nil {
			return nil, err
		}

		service := output.Service

		// filter out services not owned by this External DNS
		if p.ownerID != "" && aws.StringValue(service.CreatorRequestId) != p.ownerID {
			continue
		}

		services[aws.StringValue(service.Name)] = service
	}

	return services, nil
}

func (p *AWSSDProvider) ListInstancesByServiceId(serviceId *string) ([]*sd.InstanceSummary, error) {
	instances := make([]*sd.InstanceSummary, 0)

	f := func(resp *sd.ListInstancesOutput, lastPage bool) bool {
		instances = append(instances, resp.Instances...)

		return true
	}

	err := p.client.ListInstancesPages(&sd.ListInstancesInput{
		ServiceId: serviceId,
	}, f)
	if err != nil {
		return nil, err
	}

	return instances, nil
}

func (p *AWSSDProvider) CreateService(namespaceId *string, srvName *string, ep *endpoint.Endpoint) (*sd.ServiceSummary, error) {
	log.Infof("Creating a new service \"%s\" in \"%s\" namespace", *srvName, *namespaceId)

	srvType := p.serviceTypeFromEndpoint(ep)
	routingPolicy := p.routingPolicyFromEndpoint(ep)

	ttl := int64(sdDefaultRecordTTL)
	if ep.RecordTTL.IsConfigured() {
		ttl = int64(ep.RecordTTL)
	}

	if !p.dryRun {
		out, err := p.client.CreateService(&sd.CreateServiceInput{
			Name:             srvName,
			Description:      aws.String(strings.Replace(sdServiceDescription, "<owner-id>", p.ownerID, 1)),
			CreatorRequestId: aws.String(p.ownerID),
			DnsConfig: &sd.DnsConfig{
				NamespaceId:   namespaceId,
				RoutingPolicy: aws.String(routingPolicy),
				DnsRecords: []*sd.DnsRecord{{
					Type: aws.String(srvType),
					TTL:  aws.Int64(ttl),
				}},
			},
		})
		if err != nil {
			return nil, err
		}

		return serviceToServiceSummary(out.Service), nil
	}

	// return mock service summary in case of dry run
	return &sd.ServiceSummary{Id: aws.String("dry-run-service"), Name: aws.String("dry-run-service")}, nil
}

func (p *AWSSDProvider) UpdateService(service *sd.Service, ep *endpoint.Endpoint) error {
	log.Infof("Updating service \"%s\" with TTL set to \"%d\"", *service.Name, ep.RecordTTL)

	srvType := p.serviceTypeFromEndpoint(ep)

	ttl := int64(sdDefaultRecordTTL)
	if ep.RecordTTL.IsConfigured() {
		ttl = int64(ep.RecordTTL)
	}

	if !p.dryRun {
		_, err := p.client.UpdateService(&sd.UpdateServiceInput{
			Id: service.Id,
			Service: &sd.ServiceChange{
				DnsConfig: &sd.DnsConfigChange{
					DnsRecords: []*sd.DnsRecord{{
						Type: aws.String(srvType),
						TTL:  aws.Int64(ttl),
					}},
				}}})
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *AWSSDProvider) RegisterInstance(service *sd.ServiceSummary, ep *endpoint.Endpoint) error {
	for _, target := range ep.Targets {
		log.Infof("Registering a new instance \"%s\" for service \"%s\" (%s)", target, *service.Name, *service.Id)

		attr := make(map[string]*string)

		if ep.RecordType == endpoint.RecordTypeCNAME {
			if p.isAWSLoadBalancer(target) {
				attr["AWS_ALIAS_DNS_NAME"] = aws.String(target)
			} else {
				attr["AWS_INSTANCE_CNAME"] = aws.String(target)
			}
		} else if ep.RecordType == endpoint.RecordTypeA {
			attr["AWS_INSTANCE_IPV4"] = aws.String(target)
		} else {
			return fmt.Errorf("FATAL ERROR: Invalid endpoint type (%v)", ep)
		}

		if !p.dryRun {
			_, err := p.client.RegisterInstance(&sd.RegisterInstanceInput{
				ServiceId:  service.Id,
				Attributes: attr,
				InstanceId: aws.String(p.targetToInstanceId(target)),
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *AWSSDProvider) DeregisterInstance(service *sd.ServiceSummary, ep *endpoint.Endpoint) error {
	for _, target := range ep.Targets {
		log.Infof("De-registering an instance \"%s\" for service \"%s\" (%s)", target, *service.Name, *service.Id)

		if !p.dryRun {
			_, err := p.client.DeregisterInstance(&sd.DeregisterInstanceInput{
				InstanceId: aws.String(p.targetToInstanceId(target)),
				ServiceId:  service.Id,
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// Instance ID length is limited by AWS API to 64 characters. For longer strings SHA-256 hash will be used instead of
// the verbatim target to limit the length.
func (p *AWSSDProvider) targetToInstanceId(target string) string {
	if len(target) > 64 {
		hash := sha256.Sum256([]byte(strings.ToLower(target)))
		return hex.EncodeToString(hash[:])
	}

	return strings.ToLower(target)
}

func namespaceToNamespaceSummary(namespace *sd.Namespace) *sd.NamespaceSummary {
	if namespace == nil {
		return nil
	}

	return &sd.NamespaceSummary{
		Id:   namespace.Id,
		Type: namespace.Type,
		Name: namespace.Name,
		Arn:  namespace.Arn,
	}
}

func serviceToServiceSummary(service *sd.Service) *sd.ServiceSummary {
	if service == nil {
		return nil
	}

	return &sd.ServiceSummary{
		Name:          service.Name,
		Id:            service.Id,
		Arn:           service.Arn,
		Description:   service.Description,
		InstanceCount: service.InstanceCount,
	}
}

func instanceToInstanceSummary(instance *sd.Instance) *sd.InstanceSummary {
	if instance == nil {
		return nil
	}

	return &sd.InstanceSummary{
		Id:         instance.Id,
		Attributes: instance.Attributes,
	}
}

func (p *AWSSDProvider) changesByNamespaceId(namespaces []*sd.NamespaceSummary, changes []*endpoint.Endpoint) map[string][]*endpoint.Endpoint {
	changesByNsId := make(map[string][]*endpoint.Endpoint)

	for _, ns := range namespaces {
		changesByNsId[*ns.Id] = []*endpoint.Endpoint{}
	}

	for _, c := range changes {
		// trim the trailing dot from hostname if any
		hostname := strings.TrimSuffix(c.DNSName, ".")
		nsName, _ := p.parseHostname(hostname)

		matchingNamespaces := matchingNamespaces(nsName, namespaces)
		if len(matchingNamespaces) == 0 {
			log.Warnf("Skipping record %s because no namespace matching record DNS Name was detected ", c.String())
			continue
		}
		for _, ns := range matchingNamespaces {
			changesByNsId[*ns.Id] = append(changesByNsId[*ns.Id], c)
		}
	}

	// separating a change could lead to empty sub changes, remove them here.
	for zone, change := range changesByNsId {
		if len(change) == 0 {
			delete(changesByNsId, zone)
		}
	}

	return changesByNsId
}

// returns list of all namespaces matching given hostname
func matchingNamespaces(hostname string, namespaces []*sd.NamespaceSummary) []*sd.NamespaceSummary {
	matchingNamespaces := make([]*sd.NamespaceSummary, 0)

	for _, ns := range namespaces {
		if *ns.Name == hostname {
			matchingNamespaces = append(matchingNamespaces, ns)
		}
	}

	return matchingNamespaces
}

// parse hostname to namespace (domain) and service
func (p *AWSSDProvider) parseHostname(hostname string) (namespace string, service string) {
	parts := strings.Split(hostname, ".")
	service = parts[0]
	namespace = strings.Join(parts[1:], ".")
	return
}

// determine service routing policy based on endpoint type
func (p *AWSSDProvider) routingPolicyFromEndpoint(ep *endpoint.Endpoint) string {
	if ep.RecordType == endpoint.RecordTypeA {
		return sd.RoutingPolicyMultivalue
	}

	return sd.RoutingPolicyWeighted
}

// determine service type (A, CNAME) from given endpoint
func (p *AWSSDProvider) serviceTypeFromEndpoint(ep *endpoint.Endpoint) string {
	if ep.RecordType == endpoint.RecordTypeCNAME {
		// FIXME service type is derived from the first target only. Theoretically this may be problem.
		// But I don't see a scenario where one endpoint contains targets of different types.
		if p.isAWSLoadBalancer(ep.Targets[0]) {
			// ALIAS target uses DNS record type of A
			return sd.RecordTypeA
		}
		return sd.RecordTypeCname
	}
	return sd.RecordTypeA
}

// determine if a given hostname belongs to an AWS load balancer
func (p *AWSSDProvider) isAWSLoadBalancer(hostname string) bool {
	return strings.HasSuffix(hostname, sdElbHostnameSuffix)
}
