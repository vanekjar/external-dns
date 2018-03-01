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
	"errors"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	sd "github.com/aws/aws-sdk-go/service/servicediscovery"
	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/internal/testutils"
	"github.com/kubernetes-incubator/external-dns/plan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile time check for interface conformance
var _ AWSServiceDiscoveryAPI = &AWSServiceDiscoveryAPIStub{}

type AWSServiceDiscoveryAPIStub struct {
	// map[namespace_id]namespace
	namespaces map[string]*sd.Namespace

	// map[namespace_id] => map[service_id]instance
	services map[string]map[string]*sd.Service

	// map[service_id] => map[inst_id]instance
	instances map[string]map[string]*sd.Instance
}

func (s *AWSServiceDiscoveryAPIStub) CreateService(input *sd.CreateServiceInput) (*sd.CreateServiceOutput, error) {

	srv := &sd.Service{
		Id:               aws.String(string(rand.Intn(10000))),
		DnsConfig:        input.DnsConfig,
		Name:             input.Name,
		Description:      input.Description,
		CreateDate:       aws.Time(time.Now()),
		CreatorRequestId: input.CreatorRequestId,
	}

	nsServices, ok := s.services[*input.DnsConfig.NamespaceId]
	if !ok {
		nsServices = make(map[string]*sd.Service)
		s.services[*input.DnsConfig.NamespaceId] = nsServices
	}
	nsServices[*srv.Id] = srv

	return &sd.CreateServiceOutput{
		Service: srv,
	}, nil
}

func (s *AWSServiceDiscoveryAPIStub) DeregisterInstance(input *sd.DeregisterInstanceInput) (*sd.DeregisterInstanceOutput, error) {
	serviceInstances := s.instances[*input.ServiceId]
	delete(serviceInstances, *input.InstanceId)

	return &sd.DeregisterInstanceOutput{}, nil
}

func (s *AWSServiceDiscoveryAPIStub) GetService(input *sd.GetServiceInput) (*sd.GetServiceOutput, error) {
	for _, entry := range s.services {
		srv, ok := entry[*input.Id]
		if ok {
			return &sd.GetServiceOutput{
				Service: srv,
			}, nil
		}
	}

	return nil, errors.New("service not found")
}

func (s *AWSServiceDiscoveryAPIStub) ListInstancesPages(input *sd.ListInstancesInput, fn func(*sd.ListInstancesOutput, bool) bool) error {
	instances := make([]*sd.InstanceSummary, 0)

	for _, inst := range s.instances[*input.ServiceId] {
		instances = append(instances, instanceToInstanceSummary(inst))
	}

	fn(&sd.ListInstancesOutput{
		Instances: instances,
	}, true)

	return nil
}

func (s *AWSServiceDiscoveryAPIStub) ListNamespacesPages(input *sd.ListNamespacesInput, fn func(*sd.ListNamespacesOutput, bool) bool) error {
	namespaces := make([]*sd.NamespaceSummary, 0)

	filter := input.Filters[0]

	for _, ns := range s.namespaces {
		if filter != nil && *filter.Name == sd.NamespaceFilterNameType {
			if *ns.Type != *filter.Values[0] {
				// skip namespaces not matching filter
				continue
			}
		}
		namespaces = append(namespaces, namespaceToNamespaceSummary(ns))
	}

	fn(&sd.ListNamespacesOutput{
		Namespaces: namespaces,
	}, true)

	return nil
}

func (s *AWSServiceDiscoveryAPIStub) ListServicesPages(input *sd.ListServicesInput, fn func(*sd.ListServicesOutput, bool) bool) error {
	services := make([]*sd.ServiceSummary, 0)

	// get namespace filter
	filter := input.Filters[0]
	if filter == nil || *filter.Name != sd.ServiceFilterNameNamespaceId {
		return errors.New("missing namespace filter")
	}
	nsId := filter.Values[0]

	for _, srv := range s.services[*nsId] {
		services = append(services, serviceToServiceSummary(srv))
	}

	fn(&sd.ListServicesOutput{
		Services: services,
	}, true)

	return nil
}

func (s *AWSServiceDiscoveryAPIStub) RegisterInstance(input *sd.RegisterInstanceInput) (*sd.RegisterInstanceOutput, error) {

	srvInstances, ok := s.instances[*input.ServiceId]
	if !ok {
		srvInstances = make(map[string]*sd.Instance)
		s.instances[*input.ServiceId] = srvInstances
	}

	srvInstances[*input.InstanceId] = &sd.Instance{
		Id:               input.InstanceId,
		Attributes:       input.Attributes,
		CreatorRequestId: input.CreatorRequestId,
	}

	return &sd.RegisterInstanceOutput{}, nil
}

func (s *AWSServiceDiscoveryAPIStub) UpdateService(input *sd.UpdateServiceInput) (*sd.UpdateServiceOutput, error) {
	out, err := s.GetService(&sd.GetServiceInput{Id: input.Id})
	if err != nil {
		return nil, err
	}

	origSrv := out.Service
	updateSrv := input.Service

	origSrv.Description = updateSrv.Description
	origSrv.DnsConfig.DnsRecords = updateSrv.DnsConfig.DnsRecords

	return &sd.UpdateServiceOutput{}, nil
}

func newAWSSDProvider(api AWSServiceDiscoveryAPI, domainFilter DomainFilter, namespaceTypeFilter NamespaceTypeFilter, ownerId string) *AWSSDProvider {
	return &AWSSDProvider{
		client:              api,
		namespaceFilter:     domainFilter,
		namespaceTypeFilter: namespaceTypeFilter.toAwsApiRequestFilter(),
		ownerID:             ownerId,
		dryRun:              false,
	}
}

func TestAWSSDProvider_Records(t *testing.T) {
	namespaces := map[string]*sd.Namespace{
		"private": {
			Id:   aws.String("private"),
			Name: aws.String("private.com"),
			Type: aws.String(sd.NamespaceTypeDnsPrivate),
		},
	}

	services := map[string]map[string]*sd.Service{
		"private": {
			"a-srv": {
				Id:               aws.String("a-srv"),
				Name:             aws.String("service1"),
				CreatorRequestId: aws.String(""),
				DnsConfig: &sd.DnsConfig{
					NamespaceId:   aws.String("private"),
					RoutingPolicy: aws.String(sd.RoutingPolicyWeighted),
					DnsRecords: []*sd.DnsRecord{{
						Type: aws.String(sd.RecordTypeA),
						TTL:  aws.Int64(100),
					}},
				},
			},
			"alias-srv": {
				Id:               aws.String("alias-srv"),
				Name:             aws.String("service2"),
				CreatorRequestId: aws.String(""),
				DnsConfig: &sd.DnsConfig{
					NamespaceId:   aws.String("private"),
					RoutingPolicy: aws.String(sd.RoutingPolicyWeighted),
					DnsRecords: []*sd.DnsRecord{{
						Type: aws.String(sd.RecordTypeA),
						TTL:  aws.Int64(100),
					}},
				},
			},
			"cname-srv": {
				Id:               aws.String("cname-srv"),
				Name:             aws.String("service3"),
				CreatorRequestId: aws.String(""),
				DnsConfig: &sd.DnsConfig{
					NamespaceId:   aws.String("private"),
					RoutingPolicy: aws.String(sd.RoutingPolicyWeighted),
					DnsRecords: []*sd.DnsRecord{{
						Type: aws.String(sd.RecordTypeCname),
						TTL:  aws.Int64(80),
					}},
				},
			},
		},
	}

	instances := map[string]map[string]*sd.Instance{
		"a-srv": {
			"1.2.3.4": {
				Id: aws.String("1.2.3.4"),
				Attributes: map[string]*string{
					"AWS_INSTANCE_IPV4": aws.String("1.2.3.4"),
				},
			},
			"1.2.3.5": {
				Id: aws.String("1.2.3.5"),
				Attributes: map[string]*string{
					"AWS_INSTANCE_IPV4": aws.String("1.2.3.5"),
				},
			},
		},
		"alias-srv": {
			"load-balancer.us-east-1.elb.amazonaws.com": {
				Id: aws.String("load-balancer.us-east-1.elb.amazonaws.com"),
				Attributes: map[string]*string{
					"AWS_ALIAS_DNS_NAME": aws.String("load-balancer.us-east-1.elb.amazonaws.com"),
				},
			},
		},
		"cname-srv": {
			"cname.target.com": {
				Id: aws.String("cname.target.com"),
				Attributes: map[string]*string{
					"AWS_INSTANCE_CNAME": aws.String("cname.target.com"),
				},
			},
		},
	}

	expectedEndpoints := []*endpoint.Endpoint{
		{DNSName: "service1.private.com", Targets: endpoint.Targets{"1.2.3.4", "1.2.3.5"}, RecordType: endpoint.RecordTypeA, RecordTTL: 100},
		{DNSName: "service2.private.com", Targets: endpoint.Targets{"load-balancer.us-east-1.elb.amazonaws.com"}, RecordType: endpoint.RecordTypeCNAME, RecordTTL: 100},
		{DNSName: "service3.private.com", Targets: endpoint.Targets{"cname.target.com"}, RecordType: endpoint.RecordTypeCNAME, RecordTTL: 80},
	}

	api := &AWSServiceDiscoveryAPIStub{
		namespaces: namespaces,
		services:   services,
		instances:  instances,
	}

	provider := newAWSSDProvider(api, NewDomainFilter([]string{}), NewNamespaceTypeFilter(""), "")

	endpoints, _ := provider.Records()

	assert.True(t, testutils.SameEndpoints(expectedEndpoints, endpoints), "expected and actual endpoints don't match, expected=%v, actual=%v", expectedEndpoints, endpoints)
}

func TestAWSSDProvider_ApplyChanges(t *testing.T) {
	namespaces := map[string]*sd.Namespace{
		"private": {
			Id:   aws.String("private"),
			Name: aws.String("private.com"),
			Type: aws.String(sd.NamespaceTypeDnsPrivate),
		},
	}

	api := &AWSServiceDiscoveryAPIStub{
		namespaces: namespaces,
		services:   make(map[string]map[string]*sd.Service),
		instances:  make(map[string]map[string]*sd.Instance),
	}

	expectedEndpoints := []*endpoint.Endpoint{
		{DNSName: "service1.private.com", Targets: endpoint.Targets{"1.2.3.4", "1.2.3.5"}, RecordType: endpoint.RecordTypeA, RecordTTL: 60},
		{DNSName: "service2.private.com", Targets: endpoint.Targets{"load-balancer.us-east-1.elb.amazonaws.com"}, RecordType: endpoint.RecordTypeCNAME, RecordTTL: 80},
		{DNSName: "service3.private.com", Targets: endpoint.Targets{"cname.target.com"}, RecordType: endpoint.RecordTypeCNAME, RecordTTL: 100},
	}

	provider := newAWSSDProvider(api, NewDomainFilter([]string{}), NewNamespaceTypeFilter(""), "")

	// apply creates
	provider.ApplyChanges(&plan.Changes{
		Create: expectedEndpoints,
	})

	// make sure services were created
	assert.Len(t, api.services["private"], 3)
	existingServices, _ := provider.ListServicesByNamespaceId(namespaces["private"].Id)
	assert.NotNil(t, existingServices["service1"])
	assert.NotNil(t, existingServices["service2"])
	assert.NotNil(t, existingServices["service3"])

	// make sure instances were registered
	endpoints, _ := provider.Records()
	assert.True(t, testutils.SameEndpoints(expectedEndpoints, endpoints), "expected and actual endpoints don't match, expected=%v, actual=%v", expectedEndpoints, endpoints)

	// apply deletes
	provider.ApplyChanges(&plan.Changes{
		Delete: expectedEndpoints,
	})

	// make sure all instances are gone
	endpoints, _ = provider.Records()
	assert.Empty(t, endpoints)
}

func TestAWSSDProvider_ListNamespaces(t *testing.T) {
	namespaces := map[string]*sd.Namespace{
		"private": {
			Id:   aws.String("private"),
			Name: aws.String("private.com"),
			Type: aws.String(sd.NamespaceTypeDnsPrivate),
		},
		"public": {
			Id:   aws.String("public"),
			Name: aws.String("public.com"),
			Type: aws.String(sd.NamespaceTypeDnsPublic),
		},
	}

	api := &AWSServiceDiscoveryAPIStub{
		namespaces: namespaces,
	}

	for _, tc := range []struct {
		msg                 string
		domainFilter        DomainFilter
		namespaceTypeFilter NamespaceTypeFilter
		expectedNamespaces  []*sd.NamespaceSummary
	}{
		{"public filter", NewDomainFilter([]string{}), NewNamespaceTypeFilter("public"), []*sd.NamespaceSummary{namespaceToNamespaceSummary(namespaces["public"])}},
		{"private filter", NewDomainFilter([]string{}), NewNamespaceTypeFilter("private"), []*sd.NamespaceSummary{namespaceToNamespaceSummary(namespaces["private"])}},
		{"domain filter", NewDomainFilter([]string{"public.com"}), NewNamespaceTypeFilter(""), []*sd.NamespaceSummary{namespaceToNamespaceSummary(namespaces["public"])}},
		{"non-existing domain", NewDomainFilter([]string{"xxx.com"}), NewNamespaceTypeFilter(""), []*sd.NamespaceSummary{}},
	} {
		provider := newAWSSDProvider(api, tc.domainFilter, tc.namespaceTypeFilter, "")

		result, err := provider.ListNamespaces()
		require.NoError(t, err)

		if !reflect.DeepEqual(result, tc.expectedNamespaces) {
			t.Errorf("AWSSDProvider.ListNamespaces() error = %v, wantErr %v", result, tc.expectedNamespaces)
		}
	}
}

func TestAWSSDProvider_ListServicesByNamespace(t *testing.T) {
	namespaces := map[string]*sd.Namespace{
		"private": {
			Id:   aws.String("private"),
			Name: aws.String("private.com"),
			Type: aws.String(sd.NamespaceTypeDnsPrivate),
		},
		"public": {
			Id:   aws.String("public"),
			Name: aws.String("public.com"),
			Type: aws.String(sd.NamespaceTypeDnsPublic),
		},
	}

	services := map[string]map[string]*sd.Service{
		"private": {
			"srv1": {
				Id:               aws.String("srv1"),
				Name:             aws.String("service1"),
				CreatorRequestId: aws.String("owner1"),
			},
			"srv2": {
				Id:               aws.String("srv2"),
				Name:             aws.String("service2"),
				CreatorRequestId: aws.String("owner2"),
			},
		},
		"public": {
			"srv3": {
				Id:               aws.String("srv3"),
				Name:             aws.String("service3"),
				CreatorRequestId: aws.String("owner1"),
			},
		},
	}

	api := &AWSServiceDiscoveryAPIStub{
		namespaces: namespaces,
		services:   services,
	}

	for _, tc := range []struct {
		msg              string
		ownerFilter      string
		expectedServices map[string]*sd.Service
	}{
		{"owner filter", "owner1", map[string]*sd.Service{"service1": services["private"]["srv1"]}},
		{"no filter", "", map[string]*sd.Service{"service1": services["private"]["srv1"], "service2": services["private"]["srv2"]}},
	} {
		provider := newAWSSDProvider(api, NewDomainFilter([]string{}), NewNamespaceTypeFilter(""), tc.ownerFilter)

		result, err := provider.ListServicesByNamespaceId(namespaces["private"].Id)
		require.NoError(t, err)

		if !reflect.DeepEqual(result, tc.expectedServices) {
			t.Errorf("AWSSDProvider.ListServicesByNamespaceId() error = %v, wantErr %v", result, tc.expectedServices)
		}
	}
}

func TestAWSSDProvider_ListInstancesByService(t *testing.T) {
	namespaces := map[string]*sd.Namespace{
		"private": {
			Id:   aws.String("private"),
			Name: aws.String("private.com"),
			Type: aws.String(sd.NamespaceTypeDnsPrivate),
		},
	}

	services := map[string]map[string]*sd.Service{
		"private": {
			"srv1": {
				Id:               aws.String("srv1"),
				Name:             aws.String("service1"),
				CreatorRequestId: aws.String("owner1"),
			},
			"srv2": {
				Id:               aws.String("srv2"),
				Name:             aws.String("service2"),
				CreatorRequestId: aws.String("owner2"),
			},
		},
	}

	instances := map[string]map[string]*sd.Instance{
		"srv1": {
			"inst1": {
				Id: aws.String("inst1"),
				Attributes: map[string]*string{
					"AWS_INSTANCE_IPV4": aws.String("1.2.3.4"),
				},
			},
			"inst2": {
				Id: aws.String("inst2"),
				Attributes: map[string]*string{
					"AWS_INSTANCE_IPV4": aws.String("1.2.3.5"),
				},
			},
		},
	}

	api := &AWSServiceDiscoveryAPIStub{
		namespaces: namespaces,
		services:   services,
		instances:  instances,
	}

	provider := newAWSSDProvider(api, NewDomainFilter([]string{}), NewNamespaceTypeFilter(""), "")

	result, err := provider.ListInstancesByServiceId(services["private"]["srv1"].Id)
	require.NoError(t, err)

	expectedInstances := []*sd.InstanceSummary{instanceToInstanceSummary(instances["srv1"]["inst1"]), instanceToInstanceSummary(instances["srv1"]["inst2"])}

	if !reflect.DeepEqual(result, expectedInstances) {
		t.Errorf("AWSSDProvider.ListInstancesByServiceId() error = %v, wantErr %v", result, expectedInstances)
	}
}

func TestAWSSDProvider_CreateService(t *testing.T) {
	namespaces := map[string]*sd.Namespace{
		"private": {
			Id:   aws.String("private"),
			Name: aws.String("private.com"),
			Type: aws.String(sd.NamespaceTypeDnsPrivate),
		},
	}

	api := &AWSServiceDiscoveryAPIStub{
		namespaces: namespaces,
		services:   make(map[string]map[string]*sd.Service),
	}

	expectedServices := make(map[string]*sd.Service)

	provider := newAWSSDProvider(api, NewDomainFilter([]string{}), NewNamespaceTypeFilter(""), "owner-id")

	// A type
	provider.CreateService(aws.String("private"), aws.String("A-srv"), &endpoint.Endpoint{
		RecordType: endpoint.RecordTypeA,
		RecordTTL:  60,
		Targets:    endpoint.Targets{"1.2.3.4"},
	})
	expectedServices["A-srv"] = &sd.Service{
		Name:             aws.String("A-srv"),
		CreatorRequestId: aws.String("owner-id"),
		DnsConfig: &sd.DnsConfig{
			NamespaceId:   aws.String("private"),
			RoutingPolicy: aws.String(sd.RoutingPolicyMultivalue),
			DnsRecords: []*sd.DnsRecord{{
				Type: aws.String(sd.RecordTypeA),
				TTL:  aws.Int64(60),
			}},
		},
	}

	// CNAME type
	provider.CreateService(aws.String("private"), aws.String("CNAME-srv"), &endpoint.Endpoint{
		RecordType: endpoint.RecordTypeCNAME,
		RecordTTL:  80,
		Targets:    endpoint.Targets{"cname.target.com"},
	})
	expectedServices["CNAME-srv"] = &sd.Service{
		Name:             aws.String("CNAME-srv"),
		CreatorRequestId: aws.String("owner-id"),
		DnsConfig: &sd.DnsConfig{
			NamespaceId:   aws.String("private"),
			RoutingPolicy: aws.String(sd.RoutingPolicyWeighted),
			DnsRecords: []*sd.DnsRecord{{
				Type: aws.String(sd.RecordTypeCname),
				TTL:  aws.Int64(80),
			}},
		},
	}

	// ALIAS type
	provider.CreateService(aws.String("private"), aws.String("ALIAS-srv"), &endpoint.Endpoint{
		RecordType: endpoint.RecordTypeCNAME,
		RecordTTL:  100,
		Targets:    endpoint.Targets{"load-balancer.us-east-1.elb.amazonaws.com"},
	})
	expectedServices["ALIAS-srv"] = &sd.Service{
		Name:             aws.String("ALIAS-srv"),
		CreatorRequestId: aws.String("owner-id"),
		DnsConfig: &sd.DnsConfig{
			NamespaceId:   aws.String("private"),
			RoutingPolicy: aws.String(sd.RoutingPolicyWeighted),
			DnsRecords: []*sd.DnsRecord{{
				Type: aws.String(sd.RecordTypeA),
				TTL:  aws.Int64(100),
			}},
		},
	}

	validateAWSSDServices(t, expectedServices, api.services["private"])
}

func validateAWSSDServices(t *testing.T, expected map[string]*sd.Service, services map[string]*sd.Service) {
	require.Len(t, services, len(expected))

	for _, srv := range services {
		validateAWSSDServiceEquals(t, expected[*srv.Name], srv)
	}
}

func validateAWSSDServiceEquals(t *testing.T, expected *sd.Service, srv *sd.Service) {
	assert.Equal(t, *expected.CreatorRequestId, *srv.CreatorRequestId)
	assert.Equal(t, *expected.Name, *srv.Name)
	assert.True(t, reflect.DeepEqual(*expected.DnsConfig, *srv.DnsConfig))
}

func TestAWSSDProvider_UpdateService(t *testing.T) {
	namespaces := map[string]*sd.Namespace{
		"private": {
			Id:   aws.String("private"),
			Name: aws.String("private.com"),
			Type: aws.String(sd.NamespaceTypeDnsPrivate),
		},
	}

	services := map[string]map[string]*sd.Service{
		"private": {
			"srv1": {
				Id:               aws.String("srv1"),
				Name:             aws.String("service1"),
				CreatorRequestId: aws.String("owner1"),
				DnsConfig: &sd.DnsConfig{
					NamespaceId:   aws.String("private"),
					RoutingPolicy: aws.String(sd.RoutingPolicyMultivalue),
					DnsRecords: []*sd.DnsRecord{{
						Type: aws.String(sd.RecordTypeA),
						TTL:  aws.Int64(60),
					}},
				},
			},
		},
	}

	api := &AWSServiceDiscoveryAPIStub{
		namespaces: namespaces,
		services:   services,
	}

	provider := newAWSSDProvider(api, NewDomainFilter([]string{}), NewNamespaceTypeFilter(""), "owner-id")

	// update service with different TTL
	provider.UpdateService(services["private"]["srv1"], &endpoint.Endpoint{
		RecordType: endpoint.RecordTypeA,
		RecordTTL:  100,
	})

	assert.Equal(t, int64(100), *api.services["private"]["srv1"].DnsConfig.DnsRecords[0].TTL)
}

func TestAWSSDProvider_RegisterInstance(t *testing.T) {
	namespaces := map[string]*sd.Namespace{
		"private": {
			Id:   aws.String("private"),
			Name: aws.String("private.com"),
			Type: aws.String(sd.NamespaceTypeDnsPrivate),
		},
	}

	services := map[string]map[string]*sd.Service{
		"private": {
			"a-srv": {
				Id:   aws.String("a-srv"),
				Name: aws.String("service1"),
				DnsConfig: &sd.DnsConfig{
					NamespaceId:   aws.String("private"),
					RoutingPolicy: aws.String(sd.RoutingPolicyWeighted),
					DnsRecords: []*sd.DnsRecord{{
						Type: aws.String(sd.RecordTypeA),
						TTL:  aws.Int64(60),
					}},
				},
			},
			"cname-srv": {
				Id:   aws.String("cname-srv"),
				Name: aws.String("service2"),
				DnsConfig: &sd.DnsConfig{
					NamespaceId:   aws.String("private"),
					RoutingPolicy: aws.String(sd.RoutingPolicyWeighted),
					DnsRecords: []*sd.DnsRecord{{
						Type: aws.String(sd.RecordTypeCname),
						TTL:  aws.Int64(60),
					}},
				},
			},
			"alias-srv": {
				Id:   aws.String("alias-srv"),
				Name: aws.String("service3"),
				DnsConfig: &sd.DnsConfig{
					NamespaceId:   aws.String("private"),
					RoutingPolicy: aws.String(sd.RoutingPolicyWeighted),
					DnsRecords: []*sd.DnsRecord{{
						Type: aws.String(sd.RecordTypeA),
						TTL:  aws.Int64(60),
					}},
				},
			},
		},
	}

	api := &AWSServiceDiscoveryAPIStub{
		namespaces: namespaces,
		services:   services,
		instances:  make(map[string]map[string]*sd.Instance),
	}

	provider := newAWSSDProvider(api, NewDomainFilter([]string{}), NewNamespaceTypeFilter(""), "")

	expectedInstances := make(map[string]*sd.Instance)

	// IP-based instance
	provider.RegisterInstance(serviceToServiceSummary(services["private"]["a-srv"]), &endpoint.Endpoint{
		RecordType: endpoint.RecordTypeA,
		DNSName:    "service1.private.com.",
		RecordTTL:  300,
		Targets:    endpoint.Targets{"1.2.3.4", "1.2.3.5"},
	})
	expectedInstances["1.2.3.4"] = &sd.Instance{
		Id: aws.String("1.2.3.4"),
		Attributes: map[string]*string{
			"AWS_INSTANCE_IPV4": aws.String("1.2.3.4"),
		},
	}
	expectedInstances["1.2.3.5"] = &sd.Instance{
		Id: aws.String("1.2.3.5"),
		Attributes: map[string]*string{
			"AWS_INSTANCE_IPV4": aws.String("1.2.3.5"),
		},
	}

	// ALIAS instance
	provider.RegisterInstance(serviceToServiceSummary(services["private"]["alias-srv"]), &endpoint.Endpoint{
		RecordType: endpoint.RecordTypeCNAME,
		DNSName:    "service1.private.com.",
		RecordTTL:  300,
		Targets:    endpoint.Targets{"load-balancer.us-east-1.elb.amazonaws.com", "load-balancer.us-west-2.elb.amazonaws.com"},
	})
	expectedInstances["load-balancer.us-east-1.elb.amazonaws.com"] = &sd.Instance{
		Id: aws.String("load-balancer.us-east-1.elb.amazonaws.com"),
		Attributes: map[string]*string{
			"AWS_ALIAS_DNS_NAME": aws.String("load-balancer.us-east-1.elb.amazonaws.com"),
		},
	}
	expectedInstances["load-balancer.us-west-2.elb.amazonaws.com"] = &sd.Instance{
		Id: aws.String("load-balancer.us-west-2.elb.amazonaws.com"),
		Attributes: map[string]*string{
			"AWS_ALIAS_DNS_NAME": aws.String("load-balancer.us-west-2.elb.amazonaws.com"),
		},
	}

	// CNAME instance
	provider.RegisterInstance(serviceToServiceSummary(services["private"]["cname-srv"]), &endpoint.Endpoint{
		RecordType: endpoint.RecordTypeCNAME,
		DNSName:    "service2.private.com.",
		RecordTTL:  300,
		Targets:    endpoint.Targets{"cname.target.com"},
	})
	expectedInstances["cname.target.com"] = &sd.Instance{
		Id: aws.String("cname.target.com"),
		Attributes: map[string]*string{
			"AWS_INSTANCE_CNAME": aws.String("cname.target.com"),
		},
	}

	// validate instances
	for _, srvInst := range api.instances {
		for id, inst := range srvInst {
			if !reflect.DeepEqual(*expectedInstances[id], *inst) {
				t.Errorf("Instances don't match, expected = %v, actual %v", *expectedInstances[id], *inst)
			}
		}
	}
}

func TestAWSSDProvider_DeregisterInstance(t *testing.T) {
	namespaces := map[string]*sd.Namespace{
		"private": {
			Id:   aws.String("private"),
			Name: aws.String("private.com"),
			Type: aws.String(sd.NamespaceTypeDnsPrivate),
		},
	}

	services := map[string]map[string]*sd.Service{
		"private": {
			"srv1": {
				Id:               aws.String("srv1"),
				Name:             aws.String("service1"),
				CreatorRequestId: aws.String("owner1"),
			},
		},
	}

	instances := map[string]map[string]*sd.Instance{
		"srv1": {
			"1.2.3.4": {
				Id: aws.String("inst1"),
				Attributes: map[string]*string{
					"AWS_INSTANCE_IPV4": aws.String("1.2.3.4"),
				},
			},
		},
	}

	api := &AWSServiceDiscoveryAPIStub{
		namespaces: namespaces,
		services:   services,
		instances:  instances,
	}

	provider := newAWSSDProvider(api, NewDomainFilter([]string{}), NewNamespaceTypeFilter(""), "")

	provider.DeregisterInstance(serviceToServiceSummary(services["private"]["srv1"]), endpoint.NewEndpoint("srv1.private.com.", "1.2.3.4", endpoint.RecordTypeA))

	assert.Len(t, instances["srv1"], 0)
}
