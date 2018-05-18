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

package registry

import (
	"errors"

	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/plan"
	"github.com/kubernetes-incubator/external-dns/provider"
)

// AWSSDRegistry implements registry interface with ownership information associated via the CreatorID field of SD instances
type AWSSDRegistry struct {
	awsSDProvider *provider.AWSSDProvider
	ownerID       string
}

// NewAWSSDRegistry returns implementation of registry for AWS SD
func NewAWSSDRegistry(awsSDProvider *provider.AWSSDProvider, ownerID string) (*AWSSDRegistry, error) {
	if ownerID == "" {
		return nil, errors.New("owner id cannot be empty")
	}
	return &AWSSDRegistry{
		awsSDProvider: awsSDProvider,
		ownerID:       ownerID,
	}, nil
}

// Records calls AWS SD API and expects AWS SD provider to provider Owner/Resource information as a serialized
// value in the AWSSDCreatorIDLabel value in the Labels map
func (sdr *AWSSDRegistry) Records() ([]*endpoint.Endpoint, error) {
	records, err := sdr.awsSDProvider.Records()
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		labels, err := endpoint.NewLabelsFromString(record.Labels[endpoint.AWSSDCreatorIDLabel])
		if err != nil {
			// if we fail to parse the output then simply assume the endpoint is not managed by any instance of External DNS
			record.Labels = endpoint.NewLabels()
			continue
		}
		record.Labels = labels
	}

	return records, nil
}

// ApplyChanges filters out records not owned the External-DNS, additionally it adds the required label
// inserted in the AWS SD instance as a CreateID field
func (sdr *AWSSDRegistry) ApplyChanges(changes *plan.Changes) error {
	filteredChanges := &plan.Changes{
		Create:    changes.Create,
		UpdateNew: filterOwnedRecords(sdr.ownerID, changes.UpdateNew),
		UpdateOld: filterOwnedRecords(sdr.ownerID, changes.UpdateOld),
		Delete:    filterOwnedRecords(sdr.ownerID, changes.Delete),
	}

	sdr.updateCreatorLabel(filteredChanges.Create)
	sdr.updateCreatorLabel(filteredChanges.UpdateNew)
	sdr.updateCreatorLabel(filteredChanges.UpdateOld)
	sdr.updateCreatorLabel(filteredChanges.Delete)

	return sdr.awsSDProvider.ApplyChanges(filteredChanges)
}

func (sdr *AWSSDRegistry) updateCreatorLabel(endpoints []*endpoint.Endpoint) {
	for _, ep := range endpoints {
		ep.Labels[endpoint.AWSSDCreatorIDLabel] = ep.Labels.Serialize(false)
	}
}
