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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	sd "github.com/aws/aws-sdk-go/service/servicediscovery"
	"github.com/stretchr/testify/assert"
)

func TestNamespaceTypeFilterMatch(t *testing.T) {
	publicNamespace := &sd.Namespace{Type: aws.String(sd.NamespaceTypeDnsPublic)}
	privateNamespace := &sd.Namespace{Type: aws.String(sd.NamespaceTypeDnsPrivate)}

	for _, tc := range []struct {
		namespaceTypeFilter string
		namespace           *sd.Namespace
		matches             bool
	}{
		{
			"", publicNamespace, true,
		},
		{
			"", privateNamespace, true,
		},
		{
			"public", publicNamespace, true,
		},
		{
			"public", privateNamespace, false,
		},
		{
			"private", publicNamespace, false,
		},
		{
			"private", privateNamespace, true,
		},
		{
			"unknown", publicNamespace, false,
		},
	} {
		namespaceTypeFilter := NewNamespaceTypeFilter(tc.namespaceTypeFilter)
		assert.Equal(t, tc.matches, namespaceTypeFilter.Match(tc.namespace))
	}
}

func TestZoneTypeFilterToAwsApiRequestFilter(t *testing.T) {
	for _, tc := range []struct {
		namespaceTypeFilter string
		awsFilter           *sd.NamespaceFilter
	}{

		{
			"", nil,
		},
		{
			"public", &sd.NamespaceFilter{
				Name:   aws.String(sd.NamespaceFilterNameType),
				Values: []*string{aws.String(sd.NamespaceTypeDnsPublic)}},
		},
		{
			"private", &sd.NamespaceFilter{
				Name:   aws.String(sd.NamespaceFilterNameType),
				Values: []*string{aws.String(sd.NamespaceTypeDnsPrivate)}},
		},
	} {
		namespaceTypeFilter := NewNamespaceTypeFilter(tc.namespaceTypeFilter)
		assert.Equal(t, tc.awsFilter, namespaceTypeFilter.toAwsApiRequestFilter())
	}
}
