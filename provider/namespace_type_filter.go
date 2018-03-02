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
	"github.com/aws/aws-sdk-go/aws"
	sd "github.com/aws/aws-sdk-go/service/servicediscovery"
)

const (
	namespaceTypePublic  = "public"
	namespaceTypePrivate = "private"
)

// NamespaceTypeFilter holds a namespace type to filter for.
type NamespaceTypeFilter struct {
	namespaceType string
}

// NewNamespaceTypeFilter returns a new NamespaceTypeFilter given a namespace type to filter for.
func NewNamespaceTypeFilter(namespaceType string) NamespaceTypeFilter {
	return NamespaceTypeFilter{namespaceType: namespaceType}
}

// Match checks whether a namespace matches the namespace type that's filtered for.
func (f *NamespaceTypeFilter) Match(namespace *sd.Namespace) bool {
	// An empty namespace filter includes all namespaces.
	if f.namespaceType == "" {
		return true
	}

	// Given a namespace type we return true if the given namespace matches this type.
	switch f.namespaceType {
	case namespaceTypePublic:
		return aws.StringValue(namespace.Type) == sd.NamespaceTypeDnsPublic
	case namespaceTypePrivate:
		return aws.StringValue(namespace.Type) == sd.NamespaceTypeDnsPrivate
	}

	// We return false on any other path, e.g. unknown namespace type filter value.
	return false
}

// convert NamespaceTypeFilter to API request filter
func (f *NamespaceTypeFilter) toAwsApiRequestFilter() *sd.NamespaceFilter {
	switch f.namespaceType {
	case namespaceTypePublic:
		return &sd.NamespaceFilter{
			Name:   aws.String(sd.NamespaceFilterNameType),
			Values: []*string{aws.String(sd.NamespaceTypeDnsPublic)},
		}
	case namespaceTypePrivate:
		return &sd.NamespaceFilter{
			Name:   aws.String(sd.NamespaceFilterNameType),
			Values: []*string{aws.String(sd.NamespaceTypeDnsPrivate)},
		}
	default:
		return nil
	}
}
