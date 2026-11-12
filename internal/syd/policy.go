package syd

import "strings"

// ReadablePolicyRules lets workloads inspect project profiles while denying
// mutation of the policy directory and every child. Do not use this for tokens
// or private controller state, which must remain completely inaccessible.
func ReadablePolicyRules(directory string) (string, error) {
	path, err := canonicalDirectory(directory)
	if err != nil {
		return "", err
	}
	writes := "write,create,delete,rename,truncate,chmod,chattr,mkdir,rmdir,symlink"
	return strings.Join([]string{
		"allow/read,stat,readdir,readlink,chdir+" + path,
		"allow/read,stat,readdir,readlink,chdir+" + path + "/***",
		"allow/lock/read,readdir+" + path,
		"deny/" + writes + "+" + path,
		"deny/" + writes + "+" + path + "/***",
	}, "\n") + "\n", nil
}
