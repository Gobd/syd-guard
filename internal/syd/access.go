package syd

import "fmt"

// ExpandFileAccess translates public access groups into Syd path capabilities.
// It does not install rules, grant execution, or establish a Landlock ceiling.
func ExpandFileAccess(access []string) ([]string, error) {
	groups := map[string][]string{
		"read":   {"read", "stat", "readdir", "chdir", "readlink"},
		"write":  {"write", "create", "truncate", "chmod", "chattr", "mkdir", "symlink"},
		"delete": {"delete", "rmdir", "rename"},
	}
	if len(access) == 0 {
		return nil, fmt.Errorf("file access must not be empty")
	}
	seenGroups, seenCaps := map[string]bool{}, map[string]bool{}
	var result []string
	for _, group := range access {
		caps, ok := groups[group]
		if !ok || seenGroups[group] {
			return nil, fmt.Errorf("invalid or duplicate file access %q", group)
		}
		seenGroups[group] = true
		for _, cap := range caps {
			if !seenCaps[cap] {
				result = append(result, cap)
				seenCaps[cap] = true
			}
		}
	}
	return result, nil
}
