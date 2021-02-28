/*
Copyright 2018 The Kubernetes Authors.

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

package awssd

import (
	"context"
	"strconv"
	"strings"

	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	sd "github.com/aws/aws-sdk-go/service/servicediscovery"
	"github.com/linki/instrumented_http"
	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/pkg/apis/externaldns"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

const (
	sdDefaultRecordTTL = 300

	sdNamespaceTypePublic  = "public"
	sdNamespaceTypePrivate = "private"

	sdInstanceAttrIPV4  = "AWS_INSTANCE_IPV4"
	sdInstanceAttrCname = "AWS_INSTANCE_CNAME"
	sdInstanceAttrAlias = "AWS_ALIAS_DNS_NAME"
	sdInstanceAttrPort  = "AWS_INSTANCE_PORT"

	labelPreferredSRV = "awssd-preferred-srv"
)

var (
	// matches ELB with hostname format load-balancer.us-east-1.elb.amazonaws.com
	sdElbHostnameRegex = regexp.MustCompile(`.+\.[^.]+\.elb\.amazonaws\.com$`)

	// matches NLB with hostname format load-balancer.elb.us-east-1.amazonaws.com
	sdNlbHostnameRegex = regexp.MustCompile(`.+\.elb\.[^.]+\.amazonaws\.com$`)

	// matches a target of an SRV endponit in the format "priority weight port target", e.g. "0 50 80 example.com",
	// as originally sourced by external-dns to ApplyChanges.
	sdSrvHostTargetRegex = regexp.MustCompile(`^[0-9]{1,5} [0-9]{1,5} [0-9]{1,5} [^\s]+$`)

	// matches the format for the preferred SRV target of an A record. Format: "hostname TTL IN SRV priority weight port", e.g. "_srv._tcp.example.com 86400 IN SRV 0 50 80",
	sdPreferredSRVRegex = regexp.MustCompile(`^[^\s]+ [0-9]{1,10} IN SRV [0-9]{1,5} [0-9]{1,5} [0-9]{1,5}$`)
)

// AWSSDClient is the subset of the AWS Cloud Map API that we actually use. Add methods as required.
// Signatures must match exactly. Taken from https://github.com/aws/aws-sdk-go/blob/HEAD/service/servicediscovery/api.go
type AWSSDClient interface {
	CreateService(input *sd.CreateServiceInput) (*sd.CreateServiceOutput, error)
	DeregisterInstance(input *sd.DeregisterInstanceInput) (*sd.DeregisterInstanceOutput, error)
	GetService(input *sd.GetServiceInput) (*sd.GetServiceOutput, error)
	ListInstancesPages(input *sd.ListInstancesInput, fn func(*sd.ListInstancesOutput, bool) bool) error
	ListNamespacesPages(input *sd.ListNamespacesInput, fn func(*sd.ListNamespacesOutput, bool) bool) error
	ListServicesPages(input *sd.ListServicesInput, fn func(*sd.ListServicesOutput, bool) bool) error
	RegisterInstance(input *sd.RegisterInstanceInput) (*sd.RegisterInstanceOutput, error)
	UpdateService(input *sd.UpdateServiceInput) (*sd.UpdateServiceOutput, error)
	DeleteService(input *sd.DeleteServiceInput) (*sd.DeleteServiceOutput, error)
}

// AWSSDProvider is an implementation of Provider for AWS Cloud Map.
type AWSSDProvider struct {
	provider.BaseProvider
	client AWSSDClient
	dryRun bool
	// only consider namespaces ending in this suffix
	namespaceFilter endpoint.DomainFilter
	// filter namespace by type (private or public)
	namespaceTypeFilter *sd.NamespaceFilter
}

// NewAWSSDProvider initializes a new AWS Cloud Map based Provider.
func NewAWSSDProvider(domainFilter endpoint.DomainFilter, namespaceType string, assumeRole string, dryRun bool) (*AWSSDProvider, error) {
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

	if assumeRole != "" {
		log.Infof("Assuming role: %s", assumeRole)
		sess.Config.WithCredentials(stscreds.NewCredentials(sess, assumeRole))
	}

	sess.Handlers.Build.PushBack(request.MakeAddToUserAgentHandler("ExternalDNS", externaldns.Version))

	provider := &AWSSDProvider{
		client:              sd.New(sess),
		namespaceFilter:     domainFilter,
		namespaceTypeFilter: newSdNamespaceFilter(namespaceType),
		dryRun:              dryRun,
	}

	return provider, nil
}

// newSdNamespaceFilter initialized AWS SD Namespace Filter based on given string config
func newSdNamespaceFilter(namespaceTypeConfig string) *sd.NamespaceFilter {
	switch namespaceTypeConfig {
	case sdNamespaceTypePublic:
		return &sd.NamespaceFilter{
			Name:   aws.String(sd.NamespaceFilterNameType),
			Values: []*string{aws.String(sd.NamespaceTypeDnsPublic)},
		}
	case sdNamespaceTypePrivate:
		return &sd.NamespaceFilter{
			Name:   aws.String(sd.NamespaceFilterNameType),
			Values: []*string{aws.String(sd.NamespaceTypeDnsPrivate)},
		}
	default:
		return nil
	}
}

// Records returns list of all endpoints.
func (p *AWSSDProvider) Records(ctx context.Context) (endpoints []*endpoint.Endpoint, err error) {
	namespaces, err := p.ListNamespaces()
	if err != nil {
		return nil, err
	}

	for _, ns := range namespaces {
		services, err := p.ListServicesByNamespaceID(ns.Id)
		if err != nil {
			return nil, err
		}

		for _, srv := range services {
			instances, err := p.ListInstancesByServiceID(srv.Id)
			if err != nil {
				return nil, err
			}

			if len(instances) > 0 {
				ep := p.instancesToEndpoint(ns, srv, instances)
				endpoints = append(endpoints, ep...)
			}
		}
	}

	return endpoints, nil
}

func (p *AWSSDProvider) instancesToEndpoint(ns *sd.NamespaceSummary, srv *sd.Service, instances []*sd.InstanceSummary) (epList []*endpoint.Endpoint) {
	// DNS name of the record is a concatenation of service and namespace
	recordName := *srv.Name + "." + *ns.Name

	labels := endpoint.NewLabels()
	srvDescr := aws.StringValue(srv.Description)
	isAAndSRV := p.isAAndSRVService(srv)
	portsList := make([]string, 0, len(instances))
	prefSrv := ""

	if isAAndSRV {
		// if record type is A+SRV, parse the description field
		prefSrv, srvDescr, _ = p.srvDescrSplit(aws.StringValue(srv.Description))
	}

	labels[endpoint.AWSSDDescriptionLabel] = srvDescr
	newEndpoint := &endpoint.Endpoint{
		DNSName:   recordName,
		RecordTTL: endpoint.TTL(aws.Int64Value(srv.DnsConfig.DnsRecords[0].TTL)),
		Targets:   make(endpoint.Targets, 0, len(instances)),
		Labels:    labels,
	}

	for _, inst := range instances {
		// CNAME
		if inst.Attributes[sdInstanceAttrCname] != nil && aws.StringValue(srv.DnsConfig.DnsRecords[0].Type) == sd.RecordTypeCname {
			newEndpoint.RecordType = endpoint.RecordTypeCNAME
			newEndpoint.Targets = append(newEndpoint.Targets, aws.StringValue(inst.Attributes[sdInstanceAttrCname]))

			// ALIAS
		} else if inst.Attributes[sdInstanceAttrAlias] != nil {
			newEndpoint.RecordType = endpoint.RecordTypeCNAME
			newEndpoint.Targets = append(newEndpoint.Targets, aws.StringValue(inst.Attributes[sdInstanceAttrAlias]))

			// IP-based target
		} else if inst.Attributes[sdInstanceAttrIPV4] != nil {
			newEndpoint.RecordType = endpoint.RecordTypeA
			newEndpoint.Targets = append(newEndpoint.Targets, aws.StringValue(inst.Attributes[sdInstanceAttrIPV4]))
			if isAAndSRV {
				portsList = append(portsList, aws.StringValue(inst.Attributes[sdInstanceAttrPort]))
			}
		} else {
			log.Warnf("Invalid instance \"%v\" found in service \"%v\"", inst, srv.Name)
		}
	}

	epList = append(epList, newEndpoint)

	if isAAndSRV {
		// if record type is A+SRV, return also SRV endpoints
		portsList := sliceDedup(portsList)
		srvDnsName, ttl, prio, weight, _, _ := p.preferredSRVSplit(prefSrv)
		for _, port := range portsList {

			labelsSrv := endpoint.NewLabels()
			labelsSrv[endpoint.AWSSDDescriptionLabel] = srvDescr
			NewSrvEndpoint := &endpoint.Endpoint{
				DNSName:    srvDnsName,
				RecordTTL:  endpoint.TTL(ttl),
				Targets:    make(endpoint.Targets, 0, 1),
				Labels:     labelsSrv,
				RecordType: endpoint.RecordTypeSRV,
			}
			srvTarget := fmt.Sprintf("%s %s %s %s", prio, weight, port, recordName)
			NewSrvEndpoint.Targets = append(NewSrvEndpoint.Targets, srvTarget)
			epList = append(epList, NewSrvEndpoint)
		}
	}

	return
}

// ApplyChanges applies Kubernetes changes in endpoints to AWS API
func (p *AWSSDProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
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

	// SRV changes are handled separately
	changes.Create, changes.Delete, err = p.handleSRVChanges(namespaces, changes.Create, changes.Delete)
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
	updateNewMap := map[string]*endpoint.Endpoint{}
	for _, e := range changes.UpdateNew {
		updateNewMap[e.DNSName] = e
	}

	for _, old := range changes.UpdateOld {
		current := updateNewMap[old.DNSName]

		// always register (or re-register) instance with the current data
		creates = append(creates, current)

		if !old.Targets.Same(current.Targets) {
			// when targets differ the old instances need to be de-registered first
			deletes = append(deletes, old)
			// remove from both current.Targets and create.Targets the targets that appear in both of them
			p.DedupDeletesAndCreates(current, old)
		}
	}

	return creates, deletes
}

// handles SRV changes. It links related A and SRV endpoints together (in the internal relevantChanges struct).
func (p *AWSSDProvider) handleSRVChanges(namespaces []*sd.NamespaceSummary, creates []*endpoint.Endpoint, deletes []*endpoint.Endpoint) ([]*endpoint.Endpoint, []*endpoint.Endpoint, error) {
	// an internal struct of all related relevant changes to handle SRV endpoints.
	type relevantChanges struct {
		ACre   []*endpoint.Endpoint // max len is 1. This is a create endpoint with recordType A
		SRVCre []*endpoint.Endpoint // max len is 1. This is a delete endpoint with recordType SRV
		SRVDel []*endpoint.Endpoint // max len is n. These are delete endpoints with recordType SRV
	}

	createsByNamespaceID := p.changesByNamespaceID(namespaces, creates)
	deletesByNamespaceID := p.changesByNamespaceID(namespaces, deletes)

	for _, ns := range namespaces {
		nsID := *ns.Id
		nsCreates, okNsCre := createsByNamespaceID[nsID]
		nsDeletes, okNsDel := deletesByNamespaceID[nsID]
		//loop all namespaces where we have at least 1 change
		if !(okNsCre || okNsDel) {
			continue
		}

		services, err := p.ListServicesByNamespaceID(aws.String(nsID))
		if err != nil {
			return nil, nil, err
		}

		//create a map of relevant changes by host. will loop this map later to determine any SRV-related changes
		changesByHost := make(map[string]*relevantChanges)
		for _, ch := range nsCreates {
			// Cloud Map supports 1 SRV endpoint per host. Therefore, add only the first SRV endpoint per host to the "changesByHost" object.
			// This means that any SRV endpoint on the same host (after the first) is ignored.
			// The 1st SRV endpoint is added to "SRVCre" under "changesByHost". Will be used later to check if an SRV service needs to be created/updated.
			if ch.RecordType == endpoint.RecordTypeSRV {
				// the target host of the SRV endpoint is the element that links the SRV endpoint to the related A endpoint.
				// The target host of the SRV endpoint is equal to the DNS Name of the related A endpoint.
				_, host, _, _, err := p.srvHostTargetSplit(ch.Targets[0])
				if err != nil {
					return nil, nil, err
				}
				if _, ok := changesByHost[host]; !ok {
					changesByHost[host] = &relevantChanges{}
				}
				chByHost := changesByHost[host]
				// only consider 1 SRV create endpoint by host. Any other SRV create endpoint with the same host will be ignored.
				if len(chByHost.SRVCre) == 0 {
					chByHost.SRVCre = append(chByHost.SRVCre, ch)
				}

				// 1 A endpoint per host is expected. Therefore, add only the first A endpoint per host to the "changesByHost" object.
				// This means that any A endpoint on the same host (after the first) is ignored.
				// The 1st A endpoint is added to "ACre" under "changesByHost". Will be used later to check if an A service needs to be created/updated, and if it has a related SRV endpoint.
			} else if ch.RecordType == endpoint.RecordTypeA {
				host := ch.DNSName
				if _, ok := changesByHost[host]; !ok {
					changesByHost[host] = &relevantChanges{}
				}
				chByHost := changesByHost[host]
				// only consider 1 A create endpoint by host. 1 A endpoint only is expected for 1 host. If this is not the case, emit a warn.
				if len(chByHost.ACre) == 0 {
					chByHost.ACre = append(chByHost.ACre, ch)
				} else {
					log.Warnf("Skipping endpoint %s because only 1 create change is expected for A endpoint. This is unexpected.", ch.String())
				}
			}
		}
		for _, ch := range nsDeletes {
			// SRV endpoints are added to "SRVDel" under "changesByHost". Will be used later to check if an existing A+SRV service needs to be deleted/updated.
			if ch.RecordType == endpoint.RecordTypeSRV {
				_, host, _, _, err := p.srvHostTargetSplit(ch.Targets[0])
				if err != nil {
					return nil, nil, err
				}
				if _, ok := changesByHost[host]; !ok {
					changesByHost[host] = &relevantChanges{}
				}
				chByHost := changesByHost[host]
				chByHost.SRVDel = append(chByHost.SRVDel, ch)
			}
		}

		// loop the map of relevant changes by host
		for host, relCh := range changesByHost {
			_, svcName := p.parseHostname(host)

			// define some relevant variables for handling the host-level changes
			ASvc, ASvcExists := services[svcName]
			var ASvcIsAAndSRV bool
			if ASvcExists && p.isAAndSRVService(ASvc) {
				ASvcIsAAndSRV = true
			} else {
				ASvcIsAAndSRV = false
			}
			var ACreExists bool
			if len(relCh.ACre) == 1 {
				ACreExists = true
			} else {
				ACreExists = false
			}
			var SRVCreExists bool
			if len(relCh.SRVCre) == 1 {
				SRVCreExists = true
			} else {
				SRVCreExists = false
			}
			var ACre *endpoint.Endpoint
			if ACreExists {
				ACre = relCh.ACre[0]
			}
			var SRVCre *endpoint.Endpoint
			if SRVCreExists {
				SRVCre = relCh.SRVCre[0]
			}
			SRVDeletes := relCh.SRVDel
			var ASvcCurrentPrefSRV string
			var ASvcCurrentPort string
			if ASvcIsAAndSRV {
				ASvcCurrentPrefSRV, _, err = p.srvDescrSplit(aws.StringValue(ASvc.Description))
				if err != nil {
					return nil, nil, err
				}
				_, _, _, _, ASvcCurrentPort, err = p.preferredSRVSplit(ASvcCurrentPrefSRV)
				if err != nil {
					return nil, nil, err
				}
			}
			var SRVCrePrefSRV string
			if SRVCreExists {
				SRVCrePrefSRV, err = p.preferredSRVCombine(SRVCre.DNSName, SRVCre.RecordTTL, SRVCre.Targets[0])
				if err != nil {
					return nil, nil, err
				}
			}

			// set the outputs of the main if-block
			ASvcRemove := false
			newPrefSRV := ""

			//run the main if-block
			if ASvcExists {
				if ASvcIsAAndSRV {
					deleteCurrPrefSRV := false
					for _, SRVDel := range SRVDeletes {
						SRVDelPort, _, _, _, err := p.srvHostTargetSplit(SRVDel.Targets[0])
						if err != nil {
							return nil, nil, err
						}
						SRVDelPrefSRV, err := p.preferredSRVCombine(SRVDel.DNSName, SRVDel.RecordTTL, SRVDel.Targets[0])
						if err != nil {
							return nil, nil, err
						}

						if SRVDelPort != ASvcCurrentPort {
							err = p.DeleteSrvEp(SRVDel, ASvc)
						} else if SRVDelPrefSRV == ASvcCurrentPrefSRV {
							if SRVCreExists {
								deleteCurrPrefSRV = true
							} else {
								ASvcRemove = true
							}
						}
					}
					if deleteCurrPrefSRV {
						newPrefSRV = SRVCrePrefSRV
					}
				} else if SRVCreExists {
					ASvcRemove = true
				}
			} else if SRVCreExists && ACreExists {
				newPrefSRV = SRVCrePrefSRV
			}

			// set values to be returned
			if ASvcRemove {
				err = p.RemoveServiceAndInstances(ASvc)
				if err != nil {
					return nil, nil, err
				}
				emptyEp := &endpoint.Endpoint{}
				*ACre = *emptyEp
			} else if newPrefSRV != "" {
				if ACreExists {
					ACre.Labels[labelPreferredSRV] = newPrefSRV
				} else if ASvcExists {
					newACreate := p.SvcToEpNewPrefSrv(ns, ASvc, newPrefSRV)
					creates = append(creates, newACreate)
				}

			} else if ASvcExists && ASvcIsAAndSRV && ACreExists {
				ACre.Labels[labelPreferredSRV] = ASvcCurrentPrefSRV
			} else {
			}
		}
	}

	creates = sliceRemoveEmptyEp(creates)
	deletes = sliceRemoveEmptyEp(deletes)
	return creates, deletes, nil
}

func (p *AWSSDProvider) SvcToEpNewPrefSrv(ns *sd.NamespaceSummary, srv *sd.Service, labPrefSRV string) *endpoint.Endpoint {
	recordName := *srv.Name + "." + *ns.Name

	_, srvDescr, _ := p.srvDescrSplit(aws.StringValue(srv.Description))

	labels := endpoint.NewLabels()
	labels[endpoint.AWSSDDescriptionLabel] = srvDescr
	labels[labelPreferredSRV] = labPrefSRV

	newEndpoint := &endpoint.Endpoint{
		DNSName:    recordName,
		RecordTTL:  endpoint.TTL(aws.Int64Value(srv.DnsConfig.DnsRecords[0].TTL)),
		Targets:    make(endpoint.Targets, 0, 0),
		Labels:     labels,
		RecordType: endpoint.RecordTypeA,
	}

	return newEndpoint
}

func (p *AWSSDProvider) submitCreates(namespaces []*sd.NamespaceSummary, changes []*endpoint.Endpoint) error {
	changesByNamespaceID := p.changesByNamespaceID(namespaces, changes)

	for nsID, changeList := range changesByNamespaceID {
		services, err := p.ListServicesByNamespaceID(aws.String(nsID))
		if err != nil {
			return err
		}

		for _, ch := range changeList {
			// skip SRV endpoints here. SRV endpoints are handled as part of A endpoints, and registered under an A+SRV service.
			// skip endpoints with empty DNSName. These are empty endpoints, likley coming from SRV handleSRVChanges
			if ch.RecordType == endpoint.RecordTypeSRV {
				continue
			}
			_, srvName := p.parseHostname(ch.DNSName)

			expectedDescr := ch.Labels[endpoint.AWSSDDescriptionLabel]
			if prefSRV, ok := ch.Labels[labelPreferredSRV]; ok {
				expectedDescr = prefSRV + "|" + expectedDescr
			}

			srv := services[srvName]
			if srv == nil {
				// when service is missing create a new one
				srv, err = p.CreateService(&nsID, &srvName, ch)
				if err != nil {
					return err
				}
				// update local list of services
				services[*srv.Name] = srv
			} else if (ch.RecordTTL.IsConfigured() && *srv.DnsConfig.DnsRecords[0].TTL != int64(ch.RecordTTL)) ||
				aws.StringValue(srv.Description) != ch.Labels[endpoint.AWSSDDescriptionLabel] {
				// update service when TTL or Description differ
				err = p.UpdateService(srv, ch)
				if err != nil {
					return err
				}
			}

			err = p.RegisterInstance(srv, ch)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *AWSSDProvider) submitDeletes(namespaces []*sd.NamespaceSummary, changes []*endpoint.Endpoint) error {
	changesByNamespaceID := p.changesByNamespaceID(namespaces, changes)

	for nsID, changeList := range changesByNamespaceID {
		services, err := p.ListServicesByNamespaceID(aws.String(nsID))
		if err != nil {
			return err
		}

		for _, ch := range changeList {
			// don't handle SRV endpoints here. SRV endpoints are handled as part of A endpoints, and registered under an A+SRV service
			if ch.RecordType == endpoint.RecordTypeSRV {
				continue
			}
			hostname := ch.DNSName
			_, srvName := p.parseHostname(hostname)

			srv := services[srvName]
			if srv == nil {
				return fmt.Errorf("service \"%s\" is missing when trying to delete \"%v\"", srvName, hostname)
			}

			err := p.DeregisterInstance(srv, ch)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// DeleteSrvEp deletes all instances related to an outdated SRV endpoint
func (p *AWSSDProvider) DeleteSrvEp(ch *endpoint.Endpoint, svc *sd.Service) (err error) {
	epProt, _, _, _, err := p.srvHostTargetSplit(ch.Targets[0])
	if err != nil {
		return
	}
	prefSrv, _, err := p.srvDescrSplit(aws.StringValue(svc.Description))
	if err != nil {
		return err
	}
	_, _, _, _, servicePort, err := p.preferredSRVSplit(prefSrv)
	if err != nil {
		return err
	}
	if epProt != servicePort {
		// if the port on the endpoint is different from the preferred port on the service, then the endpoint is stale and all instances with that port should be removed
		// this happens when the port of a k8s NodePort is changed
		instances, err := p.ListInstancesByServiceID(svc.Id)
		if err != nil {
			return err
		}
		for _, instance := range instances {
			log.Infof("De-registering an instance \"%s\" for service \"%s\" (%s) due to wrong port", *instance.Id, *svc.Name, *svc.Id)
			if strings.Split(*instance.Id, ":")[1] == epProt {
				err = p.DeregisterInstanceById(svc.Id, instance.Id)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ListNamespaces returns all namespaces matching defined namespace filter
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

// ListServicesByNamespaceID returns list of services in given namespace. Returns map[srv_name]*sd.Service
func (p *AWSSDProvider) ListServicesByNamespaceID(namespaceID *string) (map[string]*sd.Service, error) {
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
			Values: []*string{namespaceID},
		}},
	}, f)
	if err != nil {
		return nil, err
	}

	// get detail of each listed service
	services := make(map[string]*sd.Service)
	for _, serviceID := range serviceIds {
		service, err := p.GetServiceDetail(serviceID)
		if err != nil {
			return nil, err
		}

		services[aws.StringValue(service.Name)] = service
	}

	return services, nil
}

// GetServiceDetail returns detail of given service
func (p *AWSSDProvider) GetServiceDetail(serviceID *string) (*sd.Service, error) {
	output, err := p.client.GetService(&sd.GetServiceInput{
		Id: serviceID,
	})
	if err != nil {
		return nil, err
	}

	return output.Service, nil
}

// ListInstancesByServiceID returns list of instances registered in given service.
func (p *AWSSDProvider) ListInstancesByServiceID(serviceID *string) ([]*sd.InstanceSummary, error) {
	instances := make([]*sd.InstanceSummary, 0)

	f := func(resp *sd.ListInstancesOutput, lastPage bool) bool {
		instances = append(instances, resp.Instances...)

		return true
	}

	err := p.client.ListInstancesPages(&sd.ListInstancesInput{
		ServiceId: serviceID,
	}, f)
	if err != nil {
		return nil, err
	}

	return instances, nil
}

// CreateService creates a new service in AWS API. Returns the created service.
func (p *AWSSDProvider) CreateService(namespaceID *string, srvName *string, ep *endpoint.Endpoint) (*sd.Service, error) {
	log.Infof("Creating a new service \"%s\" in \"%s\" namespace", *srvName, *namespaceID)

	srvType := p.serviceTypeFromEndpoint(ep)
	routingPolicy := p.routingPolicyFromEndpoint(ep)

	ttl := int64(sdDefaultRecordTTL)
	if ep.RecordTTL.IsConfigured() {
		ttl = int64(ep.RecordTTL)
	}

	descr := ep.Labels[endpoint.AWSSDDescriptionLabel]
	records := []*sd.DnsRecord{{
		Type: aws.String(srvType),
		TTL:  aws.Int64(ttl),
	}}

	if prefSRV, ok := ep.Labels[labelPreferredSRV]; ok {
		//when the service is A+SRV, then add the SRV-specific part
		_, srvTtl, _, _, _, err := p.preferredSRVSplit(prefSRV)
		if err != nil {
			return nil, err
		}
		descr = prefSRV + "|" + descr
		records = append(records, &sd.DnsRecord{
			Type: aws.String(sd.RecordTypeSrv),
			TTL:  aws.Int64(srvTtl),
		})
	}

	if !p.dryRun {
		out, err := p.client.CreateService(&sd.CreateServiceInput{
			Name:        srvName,
			Description: aws.String(descr),
			DnsConfig: &sd.DnsConfig{
				RoutingPolicy: aws.String(routingPolicy),
				DnsRecords:    records,
			},
			NamespaceId: namespaceID,
		})
		if err != nil {
			return nil, err
		}

		return out.Service, nil
	}

	// return mock service summary in case of dry run
	return &sd.Service{Id: aws.String("dry-run-service"), Name: aws.String("dry-run-service")}, nil
}

// UpdateService updates the specified service with information from provided endpoint.
func (p *AWSSDProvider) UpdateService(service *sd.Service, ep *endpoint.Endpoint) error {
	log.Infof("Updating service \"%s\"", *service.Name)

	srvType := p.serviceTypeFromEndpoint(ep)

	ttl := int64(sdDefaultRecordTTL)
	if ep.RecordTTL.IsConfigured() {
		ttl = int64(ep.RecordTTL)
	}

	descr := ep.Labels[endpoint.AWSSDDescriptionLabel]
	records := []*sd.DnsRecord{{
		Type: aws.String(srvType),
		TTL:  aws.Int64(ttl),
	}}

	if prefSRV, ok := ep.Labels[labelPreferredSRV]; ok {
		//when the service is A+SRV, then add the SRV-specific part
		_, srvTtl, _, _, _, err := p.preferredSRVSplit(prefSRV)
		if err != nil {
			return err
		}
		descr = prefSRV + "|" + descr
		records = append(records, &sd.DnsRecord{
			Type: aws.String(sd.RecordTypeSrv),
			TTL:  aws.Int64(srvTtl),
		})
	}

	if !p.dryRun {
		_, err := p.client.UpdateService(&sd.UpdateServiceInput{
			Id: service.Id,
			Service: &sd.ServiceChange{
				Description: aws.String(descr),
				DnsConfig: &sd.DnsConfigChange{
					DnsRecords: records,
				}}})
		if err != nil {
			return err
		}
	}

	return nil
}

// RegisterInstance creates a new instance in given service.
func (p *AWSSDProvider) RegisterInstance(service *sd.Service, ep *endpoint.Endpoint) error {
	for _, target := range ep.Targets {
		log.Infof("Registering a new instance \"%s\" for service \"%s\" (%s)", target, *service.Name, *service.Id)

		attr := make(map[string]*string)
		targetName := target
		if ep.RecordType == endpoint.RecordTypeCNAME {
			if p.isAWSLoadBalancer(target) {
				attr[sdInstanceAttrAlias] = aws.String(target)
			} else {
				attr[sdInstanceAttrCname] = aws.String(target)
			}
		} else if ep.RecordType == endpoint.RecordTypeA {
			attr[sdInstanceAttrIPV4] = aws.String(target)
			if p.isAAndSRVService(service) {
				prefSrv, _, err := p.srvDescrSplit(aws.StringValue(service.Description))
				if err != nil {
					return err
				}
				_, _, _, _, port, err := p.preferredSRVSplit(prefSrv)
				if err != nil {
					return err
				}
				attr[sdInstanceAttrPort] = aws.String(port)
				targetName = targetName + ":" + port
			}
		} else {
			return fmt.Errorf("invalid endpoint type (%v)", ep)
		}

		if !p.dryRun {
			_, err := p.client.RegisterInstance(&sd.RegisterInstanceInput{
				ServiceId:  service.Id,
				Attributes: attr,
				InstanceId: aws.String(p.targetToInstanceID(targetName)),
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// DeregisterInstance removes an instance from given service.
func (p *AWSSDProvider) DeregisterInstance(service *sd.Service, ep *endpoint.Endpoint) error {
	for _, target := range ep.Targets {
		log.Infof("De-registering an instance \"%s\" for service \"%s\" (%s)", target, *service.Name, *service.Id)

		targetName := target
		if p.isAAndSRVService(service) {
			prefSrv, _, err := p.srvDescrSplit(aws.StringValue(service.Description))
			if err != nil {
				return err
			}
			_, _, _, _, port, err := p.preferredSRVSplit(prefSrv)
			if err != nil {
				return err
			}
			targetName = targetName + ":" + port
		}

		err := p.DeregisterInstanceById(service.Id, aws.String(p.targetToInstanceID(targetName)))
		if err != nil {
			return err
		}
	}

	return nil
}

// DeregisterInstanceById removes an instance from given service given the instance Id.
func (p *AWSSDProvider) DeregisterInstanceById(serviceId *string, instanceId *string) error {
	if !p.dryRun {
		_, err := p.client.DeregisterInstance(&sd.DeregisterInstanceInput{
			InstanceId: instanceId,
			ServiceId:  serviceId,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// RemoveServiceAndInstances deregisters all instances from the service and removes the service.
func (p *AWSSDProvider) RemoveServiceAndInstances(svc *sd.Service) error {
	instances, err := p.ListInstancesByServiceID(svc.Id)
	if err != nil {
		return err
	}
	for _, instance := range instances {
		log.Infof("De-registering an instance \"%s\" for service \"%s\" (%s) due to wrong port", *instance.Id, *svc.Name, *svc.Id)
		err = p.DeregisterInstanceById(svc.Id, instance.Id)
		if err != nil {
			return err
		}
	}
	log.Infof("Deleting a service \"%s\" (%s)", *svc.Name, *svc.Id)
	if !p.dryRun {
		_, err := p.client.DeleteService(&sd.DeleteServiceInput{
			Id: svc.Id,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// DedupDeletesAndCreates removes targets that appear identically as both deletes and creates.
// These targets are redundant and result in overlapping API calls. Without deduplication, RegisterInstance could be
// invoked while DeregisterInstance is still in progress in AWS, resulting in failure to register the instance, and
// therefore in service disruption. Redundant targets may have been introduced by updatesToCreates.
func (p *AWSSDProvider) DedupDeletesAndCreates(create *endpoint.Endpoint, delete *endpoint.Endpoint) {
	// contains all duplicate targets (appearing in both "deletes" and "creates")
	dupTargets := make([]string, 0)

	// i is the length of the deduplicated targets for the endpoint (initial targets count - duplicate targets count)
	i := 0
	// loop all targets
	for _, createTarget := range create.Targets {
		// if the target is not duplicate
		if !sliceContainsString(delete.Targets, createTarget) {
			// copy the target and increment i
			create.Targets[i] = createTarget
			i++
			// if the target is duplicate, add it to dupTargetsByEp
		} else {
			dupTargets = append(dupTargets, createTarget)
		}
	}
	// cut the slice up to i (count of deduplicated targets)
	create.Targets = create.Targets[:i]

	i = 0
	for _, deleteTarget := range delete.Targets {
		if !sliceContainsString(dupTargets, deleteTarget) {
			delete.Targets[i] = deleteTarget
			i++
		}
	}
	delete.Targets = delete.Targets[:i]
}

// Instance ID length is limited by AWS API to 64 characters. For longer strings SHA-256 hash will be used instead of
// the verbatim target to limit the length.
func (p *AWSSDProvider) targetToInstanceID(target string) string {
	if len(target) > 64 {
		hash := sha256.Sum256([]byte(strings.ToLower(target)))
		return hex.EncodeToString(hash[:])
	}

	return strings.ToLower(target)
}

// nolint: deadcode
// used from unit test
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

// nolint: deadcode
// used from unit test
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

// nolint: deadcode
// used from unit test
func instanceToInstanceSummary(instance *sd.Instance) *sd.InstanceSummary {
	if instance == nil {
		return nil
	}

	return &sd.InstanceSummary{
		Id:         instance.Id,
		Attributes: instance.Attributes,
	}
}

func (p *AWSSDProvider) changesByNamespaceID(namespaces []*sd.NamespaceSummary, changes []*endpoint.Endpoint) map[string][]*endpoint.Endpoint {
	changesByNsID := make(map[string][]*endpoint.Endpoint)

	for _, ns := range namespaces {
		changesByNsID[*ns.Id] = []*endpoint.Endpoint{}
	}

	for _, c := range changes {
		hostname := ""
		// for SRV records, use the namespace of the target A record (not the namespace of the SRV DNS name)
		if c.RecordType == endpoint.RecordTypeSRV {
			_, hostname, _, _, _ = p.srvHostTargetSplit(c.Targets[0])
		} else {
			hostname = c.DNSName
		}
		// trim the trailing dot from hostname if any
		hostname = strings.TrimSuffix(hostname, ".")
		nsName, _ := p.parseHostname(hostname)

		matchingNamespaces := matchingNamespaces(nsName, namespaces)
		if len(matchingNamespaces) == 0 {
			log.Warnf("Skipping record %s because no namespace matching record DNS Name was detected ", c.String())
			continue
		}
		for _, ns := range matchingNamespaces {
			changesByNsID[*ns.Id] = append(changesByNsID[*ns.Id], c)
		}
	}

	// separating a change could lead to empty sub changes, remove them here.
	for zone, change := range changesByNsID {
		if len(change) == 0 {
			delete(changesByNsID, zone)
		}
	}

	return changesByNsID
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
	matchElb := sdElbHostnameRegex.MatchString(hostname)
	matchNlb := sdNlbHostnameRegex.MatchString(hostname)

	return matchElb || matchNlb
}

// determine if a given service is of type A+SRV
func (p *AWSSDProvider) isAAndSRVService(srv *sd.Service) bool {
	return len(srv.DnsConfig.DnsRecords) == 2 && aws.StringValue(srv.DnsConfig.DnsRecords[0].Type) == sd.RecordTypeA && aws.StringValue(srv.DnsConfig.DnsRecords[1].Type) == sd.RecordTypeSrv
}

func (p *AWSSDProvider) srvHostTargetSplit(target string) (port string, host string, prio string, weight string, err error) {
	if !p.isSrvHostTarget(target) {
		err = fmt.Errorf("endpoint target %s is not an host-based SRV target", target)
		return
	}
	parts := strings.Split(target, " ")
	port = parts[2]
	host = parts[3]
	prio = parts[0]
	weight = parts[1]
	return
}

func (p *AWSSDProvider) preferredSRVCombine(hostname string, ttl endpoint.TTL, target string) (prefSRV string, err error) {
	port, _, prio, weight, err := p.srvHostTargetSplit(target)
	if err != nil {
		err = fmt.Errorf("endpoint target %s is not an host-based SRV target", target)
		return
	}
	prefSRV = strings.Join([]string{hostname, strconv.Itoa(int(ttl)), "IN", "SRV", prio, weight, port}, " ")
	return
}

func (p *AWSSDProvider) preferredSRVSplit(prefSRV string) (hostname string, ttl int64, prio string, weight string, port string, err error) {
	if !p.isPreferredSRV(prefSRV) {
		err = fmt.Errorf("endpoint label %s is not an preferred SRV label", prefSRV)
		return
	}
	parts := strings.Split(prefSRV, " ")
	hostname = parts[0]
	ttl, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return
	}
	prio = parts[4]
	weight = parts[5]
	port = parts[6]
	return
}

func (p *AWSSDProvider) srvDescrSplit(descr string) (prefSrv string, AWSSDDescrLabel string, err error) {
	parts := strings.Split(descr, "|")
	if len(parts) == 1 {
		err = fmt.Errorf("description is not a valid SRV description: %s", descr)
		return
	}
	prefSrv = parts[0]
	AWSSDDescrLabel = strings.Join(parts[1:], "|")
	return
}

func (p *AWSSDProvider) isSrvHostTarget(target string) bool {
	return sdSrvHostTargetRegex.MatchString(target)
}

func (p *AWSSDProvider) isPreferredSRV(target string) bool {
	return sdPreferredSRVRegex.MatchString(target)
}

func sliceDedup(s []string) []string {
	myMap := make(map[string]struct{}, len(s))
	i := 0
	for _, v := range s {
		if _, ok := myMap[v]; ok {
			continue
		}
		myMap[v] = struct{}{}
		s[i] = v
		i++
	}
	return s[:i]
}

func sliceRemoveEmptyEp(ep []*endpoint.Endpoint) []*endpoint.Endpoint {
	for i := len(ep) - 1; i >= 0; i-- {
		anEp := ep[i]
		if anEp.DNSName == "" {
			ep = append(ep[:i], ep[i+1:]...)
		}
	}
	return ep
}

// sliceContainsString determines if a given slice of strings contains a given string.
func sliceContainsString(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
