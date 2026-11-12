package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/managedstore"
)

// ManagedProfileClient must be an authenticated helper transport. Paths returned
// by it are metadata, never paths to reopen as snapshot authority.
type ManagedProfileClient interface {
	Read(context.Context, string, string) (managedstore.Response, error)
	Replace(context.Context, string, string, string, json.RawMessage) (managedstore.Response, error)
}

// ManagedProfileCatalogClient enumerates only authenticated helper registrations.
// A catalog is metadata discovery, never permission review or launch authority.
type ManagedProfileCatalogClient interface {
	ManagedProfileClient
	Catalog(context.Context) ([]managedstore.CatalogEntry, error)
}

// ManagedProfileRef is an explicitly selected registered project/profile pair.
// Possessing an ID is not authorization: construction authenticates each read.
type ManagedProfileRef struct {
	ProjectID string
	Name      string
}

type managedProfileBinding struct {
	ref       ManagedProfileRef
	source    ProfileSource
	namespace managedstore.ProjectNamespace
}

// ManagedProfileProvider adapts an explicit bounded set of authenticated helper
// registrations to the intent editor. It is not automatically installed. It does
// not enumerate folders, authorize replay or pin a workload namespace. List only
// catalogs the pairs verified at construction; every snapshot/save authenticates
// again and must retain that binding. There is no reload/session capability.
type ManagedProfileProvider struct {
	client   ManagedProfileClient
	bindings map[string]managedProfileBinding
	order    []string
}

var _ ProfileProvider = (*ManagedProfileProvider)(nil)

// NewManagedProfileProvider requires a trusted caller to supply registered refs
// and explicitly authorize editing. No production caller currently enables it.
func NewManagedProfileProvider(ctx context.Context, client ManagedProfileClient, refs []ManagedProfileRef, edit bool) (*ManagedProfileProvider, error) {
	if client == nil || len(refs) == 0 || len(refs) > 128 {
		return nil, fmt.Errorf("managed profile provider requires a client and 1..128 registered profiles")
	}
	ctx, cancel := context.WithTimeout(ctx, ProfileOperationTimeout)
	defer cancel()
	provider := &ManagedProfileProvider{client: client, bindings: make(map[string]managedProfileBinding, len(refs))}
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := validateManagedProfileRef(ref); err != nil {
			return nil, err
		}
		// Stable across provider restart, but changes for a new registration.
		id := ManagedProfileID(ref.ProjectID, ref.Name)
		if _, exists := provider.bindings[id]; exists {
			return nil, fmt.Errorf("duplicate managed profile reference")
		}
		response, err := client.Read(ctx, ref.ProjectID, ref.Name)
		if err != nil {
			return nil, err
		}
		if response.Project != ref.ProjectID || response.Name != ref.Name || response.Namespace == nil {
			return nil, fmt.Errorf("managed snapshot registration mismatch")
		}
		namespace := *response.Namespace
		if managedstore.ValidateProjectPath(namespace.Path) != nil || namespace.Path == "/" || namespace.ProjectIno == 0 || namespace.PolicyIno == 0 || namespace.ProjectDev != namespace.PolicyDev {
			return nil, fmt.Errorf("invalid managed project namespace")
		}
		source := ProfileSource{ID: id, Name: ref.Name, Project: namespace.Path, Path: filepath.Join(namespace.Path, config.ProfileFolder, ref.Name+".json"), Edit: edit}
		binding := managedProfileBinding{ref: ref, source: source, namespace: namespace}
		if _, err := binding.snapshot(response); err != nil {
			return nil, err
		}
		provider.bindings[id] = binding
		provider.order = append(provider.order, id)
	}
	return provider, nil
}

// ManagedProfileID identifies a registered project/name tuple, not authorization.
func ManagedProfileID(projectID, name string) string {
	digest := sha256.Sum256([]byte(projectID + "\x00" + name))
	return hex.EncodeToString(digest[:])
}

func validateManagedProfileRef(ref ManagedProfileRef) error {
	if len(ref.ProjectID) != 64 || config.ProfileName(ref.Name) != nil {
		return fmt.Errorf("invalid managed profile reference")
	}
	decoded, err := hex.DecodeString(ref.ProjectID)
	if err != nil || hex.EncodeToString(decoded) != ref.ProjectID {
		return fmt.Errorf("invalid registered project ID")
	}
	return nil
}

func (b managedProfileBinding) snapshot(response managedstore.Response) ([]byte, error) {
	if response.Error != "" || response.Code != "" || response.Project != b.ref.ProjectID || response.Name != b.ref.Name || response.Namespace == nil || *response.Namespace != b.namespace || !safeProfileSource(b.source) {
		return nil, fmt.Errorf("managed profile binding changed")
	}
	snapshot, err := config.ParseManagedProfileSnapshot(b.ref.Name, response.Profile)
	if err != nil || snapshot.Revision() != response.Revision {
		return nil, fmt.Errorf("invalid managed profile snapshot")
	}
	return snapshot.Bytes(), nil
}

func (p *ManagedProfileProvider) List(ctx context.Context) ([]ProfileSource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	list := make([]ProfileSource, 0, len(p.order))
	for _, id := range p.order {
		list = append(list, p.bindings[id].source)
	}
	return list, nil
}

func (p *ManagedProfileProvider) ReadSnapshot(ctx context.Context, id string) (ProfileSource, []byte, error) {
	binding, ok := p.bindings[id]
	if !ok {
		return ProfileSource{}, nil, fmt.Errorf("unknown managed profile")
	}
	ctx, cancel := context.WithTimeout(ctx, ProfileOperationTimeout)
	defer cancel()
	response, err := p.client.Read(ctx, binding.ref.ProjectID, binding.ref.Name)
	if err != nil {
		return ProfileSource{}, nil, err
	}
	data, err := binding.snapshot(response)
	if err != nil {
		return ProfileSource{}, nil, err
	}
	return binding.source, data, nil
}

func (p *ManagedProfileProvider) Replace(ctx context.Context, id, revision string, data []byte) (ProfileSource, []byte, error) {
	binding, ok := p.bindings[id]
	if !ok || !binding.source.Edit {
		return ProfileSource{}, nil, fmt.Errorf("managed profile editing unavailable")
	}
	if len(revision) != 64 {
		return ProfileSource{}, nil, fmt.Errorf("invalid expected profile revision")
	}
	if _, err := hex.DecodeString(revision); err != nil {
		return ProfileSource{}, nil, fmt.Errorf("invalid expected profile revision")
	}
	snapshot, err := config.ParseManagedProfileSnapshot(binding.ref.Name, data)
	if err != nil {
		return ProfileSource{}, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, ProfileOperationTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return ProfileSource{}, nil, err
	}
	response, err := p.client.Replace(ctx, binding.ref.ProjectID, binding.ref.Name, revision, snapshot.Bytes())
	if errors.Is(err, managedstore.ErrConflict) {
		return ProfileSource{}, nil, config.ErrProfileConflict
	}
	if err != nil {
		return ProfileSource{}, nil, err
	}
	returned, err := binding.snapshot(response)
	if err != nil || !bytes.Equal(returned, snapshot.Bytes()) {
		// A mutation may already have committed. Do not turn malformed or changed
		// bindings into a definite failure or retry the transaction automatically.
		return ProfileSource{}, nil, fmt.Errorf("%w: invalid managed replacement snapshot", managedstore.ErrIndeterminate)
	}
	return binding.source, returned, nil
}
