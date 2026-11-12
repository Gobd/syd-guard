package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/controller"
	"github.com/Gobd/syd-guard/internal/managedstore"
)

// A random helper-issued project ID denotes one fresh enrollment generation;
// the helper never reuses an ID when registering another project.
type managedReview struct {
	Project    string                        `json:"project"`
	Name       string                        `json:"name"`
	Revision   string                        `json:"revision"`
	Provenance string                        `json:"provenance"`
	Namespace  managedstore.ProjectNamespace `json:"namespace"`
}

func reviewRecord(response managedstore.Response) (managedReview, error) {
	var review managedReview
	if response.Namespace == nil || response.Project == "" || response.Name == "" || managedstore.ValidateProjectPath(response.Namespace.Path) != nil || response.Namespace.Path == "/" || response.Namespace.ProjectIno == 0 || response.Namespace.PolicyIno == 0 || response.Namespace.ProjectDev != response.Namespace.PolicyDev {
		return review, fmt.Errorf("invalid managed review binding")
	}
	snapshot, err := config.ParseManagedProfileSnapshot(response.Name, response.Profile)
	if err != nil || snapshot.Revision() != response.Revision {
		return review, fmt.Errorf("invalid managed review snapshot")
	}
	return managedReview{Project: response.Project, Name: response.Name, Revision: response.Revision, Provenance: "manual/unknown", Namespace: *response.Namespace}, nil
}

func reviewFile(state, project, name string) (string, error) {
	if config.ProfileName(name) != nil || len(project) != 64 {
		return "", fmt.Errorf("invalid managed review identity")
	}
	if decoded, err := hex.DecodeString(project); err != nil || hex.EncodeToString(decoded) != project {
		return "", fmt.Errorf("invalid managed project ID")
	}
	parent := filepath.Join(state, config.PrivateAuthorityFolder, "managed-reviews")
	if err := controller.PrepareState(parent); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(project + "\x00" + name))
	return filepath.Join(parent, hex.EncodeToString(digest[:])+".json"), nil
}

func saveManagedReview(state string, response managedstore.Response) error {
	review, err := reviewRecord(response)
	if err != nil {
		return err
	}
	path, err := reviewFile(state, review.Project, review.Name)
	if err != nil {
		return err
	}
	data, err := json.Marshal(review)
	if err != nil {
		return err
	}
	return writeReviewFile(path, data)
}

func requireManagedReview(state string, response managedstore.Response) error {
	want, err := reviewRecord(response)
	if err != nil {
		return err
	}
	path, err := reviewFile(state, want.Project, want.Name)
	if err != nil {
		return err
	}
	data, err := readReviewFile(path)
	if err != nil {
		return fmt.Errorf("review receipt unavailable: %w", err)
	}
	var got managedReview
	if err := json.Unmarshal(data, &got); err != nil || got != want {
		return fmt.Errorf("review receipt does not match the authenticated snapshot and enrollment")
	}
	canonical, err := json.Marshal(got)
	if err != nil || !bytes.Equal(data, canonical) {
		return fmt.Errorf("invalid review receipt encoding")
	}
	return nil
}
