//go:build windows

package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// setDACL makes the current user path's owner and replaces its access list
// with sddl, a "D:..." string where {user} stands for the current user. An
// elevated test run would otherwise leave Administrators as the owner.
func setDACL(t *testing.T, path, sddl string) {
	t.Helper()
	user, err := UserSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(strings.ReplaceAll(sddl, "{user}", user.String()))
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestEnsurePrivateDirWindows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Privometry")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	// Everyone may read: refused, then tightened back by EnsurePrivateDir.
	setDACL(t, dir, "D:P(A;OICI;FA;;;{user})(A;OICI;FR;;;WD)")
	if err := CheckPrivate(dir); !errors.Is(err, ErrInsecure) {
		t.Fatalf("Everyone may read: got %v, want ErrInsecure", err)
	}
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatalf("own dir should be tightened: %v", err)
	}
	f := filepath.Join(dir, "privometry.db")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(f); err != nil {
		t.Errorf("a file in the private dir inherits its access list: %v", err)
	}
}

func TestWritableByOthersWindows(t *testing.T) {
	dir := t.TempDir()
	setDACL(t, dir, "D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)")
	if w, err := WritableByOthers(dir); err != nil || w {
		t.Errorf("read for Users: writable = %v, %v; want false", w, err)
	}
	setDACL(t, dir, "D:P(A;OICI;FA;;;{user})(A;OICI;0x1301bf;;;BU)") // Modify for Users
	if w, err := WritableByOthers(dir); err != nil || !w {
		t.Errorf("modify for Users: writable = %v, %v; want true", w, err)
	}
}
