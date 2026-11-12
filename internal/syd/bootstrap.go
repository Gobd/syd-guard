package syd

import (
	"path/filepath"
	"sort"
	"strings"
)

// bootstrapRules are launch-local discovery permissions, never profile intent.
// The root Landlock ceiling remains in force; Syd's protected-path denies must
// be appended after these rules. Warn records are permission checks, not proof
// of successful filesystem operations.
func bootstrapRules() string {
	return "log/rlimit_interval:0\n" +
		"allow/lock/read,readdir,write,create,delete,rename,truncate,mkdir,rmdir,symlink,exec+/\n" +
		"allow/read,stat,readdir,readlink,chdir,write,create,delete,rename,truncate,chmod,chattr,mkdir,rmdir,symlink,exec+/***\n" +
		"warn/read,stat,readdir,readlink,chdir,write,create,delete,rename,truncate,chmod,chattr,mkdir,rmdir,symlink+/***\n" +
		// Do not turn broad discovery into access to proc fd aliases, kernel
		// interfaces or arbitrary devices. Restore only baseline device rules.
		"deny/all+/proc\ndeny/all+/proc/***\ndeny/all+/sys\ndeny/all+/sys/***\n" +
		"deny/all+/dev\ndeny/all+/dev/***\n" +
		"allow/stat+/proc/self/fd/pipe:*\n" +
		"allow/read,write,create,truncate,stat+/dev/null\nallow/read,stat+/dev/random\nallow/read,stat+/dev/urandom\n"
}

// A broad root ceiling must not permit moving or deleting a protected path's
// parent to bypass its path rules. Exact ancestor denies are placed last.
func bootstrapAncestorRules(paths []string) string {
	ancestors := map[string]bool{}
	for _, path := range paths {
		for path = filepath.Dir(path); ; path = filepath.Dir(path) {
			ancestors[path] = true
			if path == "/" {
				break
			}
		}
	}
	ordered := make([]string, 0, len(ancestors))
	for path := range ancestors {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	var rules strings.Builder
	for _, path := range ordered {
		rules.WriteString("deny/delete,rename,rmdir+" + path + "\n")
	}
	return rules.String()
}
