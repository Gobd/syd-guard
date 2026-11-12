package controller

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/Gobd/syd-guard/internal/managedstore"
)

// NewCatalogProfileProvider discovers a bounded catalog through the authenticated
// helper, then obtains exact snapshots through the same transport. It does not
// discover project folders, install a production provider, persist registration
// selection, authorize permissions or pin a session namespace. Editing still
// requires explicit caller authorization; reload/saved-decision capabilities
// remain unavailable. Reconstruct the provider to discover newly created profiles.
func NewCatalogProfileProvider(ctx context.Context, client ManagedProfileCatalogClient, edit bool) (*ManagedProfileProvider, error) {
	if client == nil {
		return nil, fmt.Errorf("managed catalog requires an authenticated client")
	}
	ctx, cancel := context.WithTimeout(ctx, ProfileOperationTimeout)
	defer cancel()
	entries, err := client.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if entries == nil || len(entries) > 128 {
		return nil, fmt.Errorf("invalid or oversized managed catalog")
	}
	refs := make([]ManagedProfileRef, 0, len(entries))
	namespaces := make(map[ManagedProfileRef]managedstore.ProjectNamespace, len(entries))
	projects := make(map[string]managedstore.ProjectNamespace)
	// Validate the entire catalog before issuing any snapshot request. Retain
	// owned namespace values rather than pointers owned by the transport.
	for _, entry := range entries {
		ref := ManagedProfileRef{ProjectID: entry.Project, Name: entry.Name}
		if err := validateManagedProfileRef(ref); err != nil {
			return nil, err
		}
		if entry.Namespace == nil || managedstore.ValidateProjectPath(entry.Namespace.Path) != nil || entry.Namespace.Path == "/" || entry.Namespace.ProjectIno == 0 || entry.Namespace.PolicyIno == 0 || entry.Namespace.ProjectDev != entry.Namespace.PolicyDev {
			return nil, fmt.Errorf("invalid catalog namespace")
		}
		decoded, err := hex.DecodeString(entry.Revision)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != entry.Revision {
			return nil, fmt.Errorf("invalid catalog revision")
		}
		if _, exists := namespaces[ref]; exists {
			return nil, fmt.Errorf("duplicate managed catalog profile")
		}
		namespace := *entry.Namespace
		if prior, exists := projects[ref.ProjectID]; exists && prior != namespace {
			return nil, fmt.Errorf("catalog registration changed namespace")
		}
		for id, other := range projects {
			if id != ref.ProjectID && (other.Path == namespace.Path || other.ProjectDev == namespace.ProjectDev && other.ProjectIno == namespace.ProjectIno || other.PolicyDev == namespace.PolicyDev && other.PolicyIno == namespace.PolicyIno) {
				return nil, fmt.Errorf("catalog contains aliased registrations")
			}
		}
		projects[ref.ProjectID] = namespace
		namespaces[ref] = namespace
		refs = append(refs, ref)
	}
	if len(refs) == 0 {
		return &ManagedProfileProvider{client: client, bindings: map[string]managedProfileBinding{}, order: []string{}}, nil
	}
	provider, err := NewManagedProfileProvider(ctx, client, refs, edit)
	if err != nil {
		return nil, err
	}
	for _, binding := range provider.bindings {
		if binding.namespace != namespaces[binding.ref] {
			return nil, fmt.Errorf("managed namespace changed between catalog and snapshot")
		}
	}
	// A concurrent operator edit can change a profile's revision after catalog
	// enumeration. The freshly authenticated snapshot is current intent, not an
	// automatically reviewed grant. CAS uses its exact revision at save time.
	return provider, nil
}
