//go:build windows

package platform

import (
	"errors"
	"fmt"
	"io/fs"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows has no mode bits. A path is private when the user owns it (SYSTEM
// or Administrators may too: they can take any file anyway) and its access
// list grants nobody else anything.

// trustedInstaller owns Windows' own files.
const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// ownerRights (S-1-3-4) stands for whoever owns the object.
const ownerRights = "S-1-3-4"

// writeRights are the rights that let a user change a file or what a folder holds.
const writeRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | 0x40 /* FILE_DELETE_CHILD */ |
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

// UserSID is the security identifier of the user running this process.
func UserSID() (*windows.SID, error) {
	t, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer t.Close()
	u, err := t.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid.Copy()
}

// TrustedOwner reports whether sid may own the user's private objects: the
// user, SYSTEM or the Administrators group.
func TrustedOwner(sid, user *windows.SID) bool {
	return sid != nil && (sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

// security reads path's owner and access list. A nil access list means
// everyone may do anything.
func security(path string) (*windows.SID, *windows.ACL, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, nil, fmt.Errorf("platform: cannot read the security of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, nil, fmt.Errorf("platform: cannot read the owner of %s: %w", path, err)
	}
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return owner, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("platform: cannot read the access list of %s: %w", path, err)
	}
	return owner, dacl, nil
}

type grant struct {
	sid  *windows.SID
	mask windows.ACCESS_MASK
}

// grants lists what an access list allows. Entries that only pass to
// children are skipped, as are denials; an allow entry of a kind this does not
// read is an error, so it is never mistaken for a harmless one.
func grants(dacl *windows.ACL) ([]grant, error) {
	var out []grant
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			out = append(out, grant{(*windows.SID)(unsafe.Pointer(&ace.SidStart)), ace.Mask})
		case windows.ACCESS_DENIED_ACE_TYPE, 6, 10, 12: // denied, denied object, denied callback, denied callback object
		default:
			return nil, fmt.Errorf("access list entry of type %d", ace.Header.AceType)
		}
	}
	return out, nil
}

func name(sid *windows.SID) string {
	if account, domain, _, err := sid.LookupAccount(""); err == nil {
		if domain != "" {
			return domain + `\` + account
		}
		return account
	}
	return sid.String()
}

func checkPrivate(path string, _ fs.FileInfo) error {
	user, err := UserSID()
	if err != nil {
		return fmt.Errorf("platform: cannot tell who you are: %w", err)
	}
	owner, dacl, err := security(path)
	if err != nil {
		return err
	}
	if !TrustedOwner(owner, user) {
		return fmt.Errorf("%w: %s is owned by %s, not you", ErrInsecure, path, name(owner))
	}
	if dacl == nil {
		return fmt.Errorf("%w: %s has no access list, so everyone may use it", ErrInsecure, path)
	}
	gs, err := grants(dacl)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInsecure, path, err)
	}
	for _, g := range gs {
		if g.mask != 0 && !TrustedOwner(g.sid, user) && g.sid.String() != ownerRights {
			return fmt.Errorf("%w: %s grants access to %s, want only you, SYSTEM and Administrators", ErrInsecure, path, name(g.sid))
		}
	}
	return nil
}

// tighten replaces the access list of a directory the user owns, when it
// lets others in, with one granting only the user, SYSTEM and Administrators.
// Files created in it inherit that list. An elevated process creates folders
// owned by Administrators rather than the user; those are tightened too.
func tighten(dir string, info fs.FileInfo) error {
	if checkPrivate(dir, info) == nil {
		return nil
	}
	user, err := UserSID()
	if err != nil {
		return nil
	}
	if owner, _, err := security(dir); err != nil || !TrustedOwner(owner, user) {
		return nil // CheckPrivate explains
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func writableByOthers(path string, _ fs.FileInfo) (bool, error) {
	owner, dacl, err := security(path)
	if err != nil {
		return false, err
	}
	if dacl == nil {
		return true, nil
	}
	gs, err := grants(dacl)
	if err != nil {
		return false, err
	}
	for _, g := range gs {
		if g.mask&writeRights == 0 {
			continue
		}
		s := g.sid.String()
		if (owner != nil && g.sid.Equals(owner)) || s == ownerRights || s == trustedInstaller ||
			g.sid.IsWellKnown(windows.WinLocalSystemSid) || g.sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			continue
		}
		return true, nil
	}
	return false, nil
}
