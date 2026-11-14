package config

import (
	"slices"
	"strings"
)

// SecretEnvName is a deliberately name-only heuristic for accidental credential
// inheritance. It is not content inspection or a guarantee that an environment
// contains no secrets. Explicit config env/passEnv and --pass-env are opt-ins.
func SecretEnvName(name string) bool {
	name = strings.ToUpper(name)
	for _, suffix := range []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "ACCESS_KEY", "ACCESS_KEY_ID", "PRIVATE_KEY", "CREDENTIAL", "CREDENTIALS"} {
		if name == suffix || strings.HasSuffix(name, "_"+suffix) {
			return true
		}
	}
	switch name {
	case "DATABASE_URL", "DATABASE_DSN", "PGPASSWORD", "MYSQL_PWD", "REDIS_URL", "SSH_AUTH_SOCK", "GPG_AGENT_INFO", "KUBECONFIG":
		return true
	}
	return false
}

// FilterAgentEnv removes inherited credential-shaped variables unless explicitly
// requested. It returns only variable NAMES for diagnostics; never their values.
func FilterAgentEnv(inherited, pass []string, configured map[string]string) (env, removed []string) {
	for _, item := range inherited {
		name, _, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		_, explicit := configured[name]
		if SecretEnvName(name) && !explicit && !slices.Contains(pass, name) {
			removed = append(removed, name)
			continue
		}
		env = append(env, item)
	}
	slices.Sort(removed)
	return env, slices.Compact(removed)
}

func ValidPassEnv(name string) bool {
	return envName.MatchString(name) && !strings.HasPrefix(name, "SYD_") && !strings.HasPrefix(name, "SG_")
}
