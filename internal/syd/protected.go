package syd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Gobd/syd-guard/internal/config"
)

// protectedNames is a bounded name-based preset, not a secret classifier.
// The same list drives generated Syd rules and file-grant checks.
var protectedNames = []string{
	".env", "*.env", ".env.*", ".ssh", ".gnupg", ".aws", ".azure", ".kube",
	".netrc", ".git-credentials", ".mozilla", "google-chrome", "chromium",
	"BraveSoftware", "microsoft-edge", config.PrivateAuthorityFolder,
}

// ProtectedPath rejects protected names and mutation of the project policy or
// its ancestors. Callers must check both the observed and resolved path.
func ProtectedPath(path, capability, policyDirectory string) bool {
	for _, component := range strings.Split(filepath.Clean(path), string(filepath.Separator)) {
		for _, name := range protectedNames {
			if matched, _ := filepath.Match(name, component); matched {
				return true
			}
		}
	}
	if policyDirectory == "" {
		return false
	}
	mutation := capability != "read" && capability != "stat" && capability != "readdir" && capability != "readlink" && capability != "chdir"
	return mutation && pathOverlaps(filepath.Clean(path), filepath.Clean(policyDirectory))
}

// ProtectedRules emits only internally generated patterns. Both root-level and
// nested forms are required: **/ does not necessarily match zero components.
func ProtectedRules(workdir string, protected []string) (string, error) {
	workdir, err := canonicalDirectory(workdir)
	if err != nil {
		return "", err
	}
	var lines []string
	for _, name := range protectedNames {
		for _, prefix := range []string{"/", "/**/"} {
			pattern := prefix + name
			lines = append(lines, "deny/all+"+pattern, "deny/all+"+pattern+"/***")
		}
	}
	for _, path := range protected {
		if err := literalPath(path); err != nil {
			return "", err
		}
		lines = append(lines, "deny/all+"+path, "deny/all+"+path+"/***")
	}
	policy := filepath.Join(workdir, ".sydguard")
	if info, err := os.Lstat(policy); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("project policy directory must not be a symlink")
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	writes := "write,create,delete,rename,truncate,chmod,chattr,mkdir,rmdir,symlink"
	lines = append(lines, "deny/"+writes+"+"+policy, "deny/"+writes+"+"+policy+"/***", "deny/delete,rename,rmdir+"+workdir)
	return strings.Join(lines, "\n") + "\n", nil
}
