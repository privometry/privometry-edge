// Package platform resolves OS-specific locations and checks file ownership and permissions.
package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// Env is the slice of the process environment that path resolution depends on.
// Tests build one directly so every OS can be exercised from any host.
type Env struct {
	GOOS   string
	Home   string
	Getenv func(string) string
}

// CurrentEnv describes the running process. Some agents run hooks with a
// trimmed environment (Antigravity passes only allowed variables), so the
// home folder, and on Windows LOCALAPPDATA and USERNAME, fall back to the
// account database when the variables are missing.
func CurrentEnv() (Env, error) {
	home, err := os.UserHomeDir()
	var u *user.User
	if err != nil {
		if u, _ = user.Current(); u == nil || u.HomeDir == "" {
			return Env{}, err
		}
		home = u.HomeDir
	}
	getenv := os.Getenv
	if runtime.GOOS == "windows" {
		getenv = func(k string) string {
			if v := os.Getenv(k); v != "" {
				return v
			}
			switch k {
			case "LOCALAPPDATA":
				return home + `\AppData\Local`
			case "USERNAME":
				if u == nil {
					u, _ = user.Current()
				}
				if u != nil {
					return u.Username[strings.LastIndex(u.Username, `\`)+1:] // DOMAIN\name
				}
			}
			return ""
		}
	}
	return Env{GOOS: runtime.GOOS, Home: home, Getenv: getenv}, nil
}

// OS returns the event-schema name of the operating system: macos, linux, windows or other.
func (e Env) OS() string {
	switch e.GOOS {
	case "darwin":
		return "macos"
	case "linux", "windows":
		return e.GOOS
	default:
		return "other"
	}
}

func (e Env) sep() string {
	if e.GOOS == "windows" {
		return `\`
	}
	return "/"
}

func (e Env) join(parts ...string) string {
	s := e.sep()
	out := strings.TrimRight(parts[0], `/\`)
	for _, p := range parts[1:] {
		out += s + strings.Trim(p, `/\`)
	}
	if e.GOOS == "windows" {
		out = strings.ReplaceAll(out, "/", `\`) // adapter definitions may write ~/.claude/settings.json
	}
	return out
}

// DataDir is where the daemon keeps its database and socket:
// ~/.privometry on macOS and Linux, %LOCALAPPDATA%\Privometry on Windows.
// PRIVOMETRY_HOME overrides it, for tests and side-by-side installs.
func (e Env) DataDir() (string, error) {
	if dir := e.Getenv("PRIVOMETRY_HOME"); dir != "" {
		return dir, nil
	}
	if e.GOOS == "windows" {
		local := e.Getenv("LOCALAPPDATA")
		if local == "" {
			return "", errors.New("platform: LOCALAPPDATA is not set")
		}
		return e.join(local, "Privometry"), nil
	}
	if e.Home == "" {
		return "", errors.New("platform: home directory is unknown")
	}
	return e.join(e.Home, ".privometry"), nil
}

// DBPath is the timeline SQLite file.
func (e Env) DBPath() (string, error) {
	dir, err := e.DataDir()
	if err != nil {
		return "", err
	}
	return e.join(dir, "privometry.db"), nil
}

// IPCAddress is the daemon endpoint: a Unix socket in the data dir, or a
// per-user named pipe on Windows. Pipes share one namespace, so with
// PRIVOMETRY_HOME set the pipe name carries a hash of that folder and a
// side-by-side daemon does not collide with the installed one.
func (e Env) IPCAddress() (string, error) {
	if e.GOOS == "windows" {
		user := e.Getenv("USERNAME")
		if user == "" {
			return "", errors.New("platform: USERNAME is not set")
		}
		name := `\\.\pipe\privometry-` + user
		if dir := e.Getenv("PRIVOMETRY_HOME"); dir != "" {
			sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimRight(dir, `/\`))))
			name += "-" + hex.EncodeToString(sum[:4])
		}
		return name, nil
	}
	dir, err := e.DataDir()
	if err != nil {
		return "", err
	}
	return e.join(dir, "privometryd.sock"), nil
}

// UserPolicyPath is the developer's override layer, ~/.privometry/policy.yaml.
func (e Env) UserPolicyPath() (string, error) {
	dir, err := e.DataDir()
	if err != nil {
		return "", err
	}
	return e.join(dir, "policy.yaml"), nil
}

// ExpandPath expands the prefixes adapter definitions may use: "~",
// "%USERPROFILE%", "%APPDATA%", "%LOCALAPPDATA%" and "%ProgramData%". Other paths are returned unchanged.
func (e Env) ExpandPath(p string) (string, error) {
	switch {
	case p == "~":
		return e.homeOrErr()
	case strings.HasPrefix(p, "~/"), strings.HasPrefix(p, `~\`):
		home, err := e.homeOrErr()
		if err != nil {
			return "", err
		}
		return e.join(home, p[2:]), nil
	}
	for _, v := range []string{"USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA"} {
		token := "%" + v + "%"
		if len(p) >= len(token) && strings.EqualFold(p[:len(token)], token) {
			val := e.Getenv(v)
			if val == "" && v == "USERPROFILE" {
				val = e.Home
			}
			if val == "" {
				return "", errors.New("platform: " + v + " is not set")
			}
			rest := p[len(token):]
			if rest == "" {
				return val, nil
			}
			return e.join(val, rest), nil
		}
	}
	return p, nil
}

func (e Env) homeOrErr() (string, error) {
	if e.Home == "" {
		return "", errors.New("platform: home directory is unknown")
	}
	return e.Home, nil
}

// DisplayPath is the path form reports and allowlists use: relative to
// repoRoot for files in the repo, ~/... for files in the home folder, and
// unchanged otherwise. Relative forms use forward slashes on Windows too, so
// they match the patterns in policy files.
func DisplayPath(p, home, repoRoot string) string {
	if rel, ok := under(p, repoRoot); ok {
		if rel == "" {
			return "."
		}
		return rel
	}
	if rel, ok := under(p, home); ok {
		if rel == "" {
			return "~"
		}
		return "~/" + rel
	}
	return p
}

// Under returns p relative to dir when p is dir ("") or inside it. A
// Windows path (separated by backslashes) comes back with forward slashes.
func Under(p, dir string) (string, bool) { return under(p, dir) }

func under(p, dir string) (string, bool) {
	if dir == "" {
		return "", false
	}
	if p == dir {
		return "", true
	}
	dir = strings.TrimRight(dir, `/\`)
	if len(p) <= len(dir)+1 || p[:len(dir)] != dir {
		return "", false
	}
	switch p[len(dir)] {
	case '/':
		return p[len(dir)+1:], true
	case '\\':
		return strings.ReplaceAll(p[len(dir)+1:], `\`, "/"), true
	}
	return "", false
}

// UnderRoot maps a logical path p into root, a folder tests use in place of
// the file system's root. A drive letter in p becomes a folder, so a simulated
// C:\Users\dev lands at root\C\Users\dev on any host. An empty root leaves p
// as the real path.
func UnderRoot(root, p string) string {
	if root == "" {
		return filepath.Join(p)
	}
	if v := filepath.VolumeName(p); v != "" {
		p = strings.TrimSuffix(v, ":") + p[len(v):]
	} else if len(p) >= 2 && p[1] == ':' {
		p = p[:1] + p[2:] // a Windows path simulated on another host
	}
	return filepath.Join(root, p)
}
