package platform

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// GitRoot returns the nearest directory at or above dir that holds .git, or
// "" outside a repository.
func GitRoot(dir string) string {
	for dir != "" {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
	return ""
}

// GitRemote returns the normalized URL of the origin remote of the repo at
// root, such as github.com/acme/api, or "" when there is none. It reads
// .git/config directly so no git binary is needed.
func GitRemote(root string) string {
	f, err := os.Open(filepath.Join(root, ".git", "config"))
	if err != nil {
		return ""
	}
	defer f.Close()
	inOrigin := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inOrigin = line == `[remote "origin"]`
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && inOrigin && strings.TrimSpace(k) == "url" {
			return NormalizeRemote(strings.TrimSpace(v))
		}
	}
	return ""
}

var scpRemote = regexp.MustCompile(`^(?:[^@/]+@)?([^:/]+):(.+)$`)

// NormalizeRemote turns git remote URLs into host/path form without scheme,
// user, port or .git suffix: git@github.com:acme/api.git and
// https://token@github.com/acme/api both give github.com/acme/api.
func NormalizeRemote(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
		if at := strings.LastIndex(strings.SplitN(u, "/", 2)[0], "@"); at >= 0 {
			u = u[at+1:]
		}
		host, path, _ := strings.Cut(u, "/")
		host, _, _ = strings.Cut(host, ":")
		u = host + "/" + path
	} else if m := scpRemote.FindStringSubmatch(u); m != nil {
		u = m[1] + "/" + m[2]
	}
	u = strings.TrimSuffix(strings.TrimSuffix(u, "/"), ".git")
	return strings.ToLower(u)
}
