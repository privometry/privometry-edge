//go:build windows

package keystore

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/privometry/privometry-oss/internal/platform"
)

// dpapi keeps each secret in a file sealed with CryptProtectData, so only the
// same user on the same machine can open it, even if the file is copied.
// The secret's name is mixed in as entropy, so one sealed file cannot stand in
// for another.
type dpapi struct{ files files }

func dpapiStore(env platform.Env) Store {
	fs, err := fileStore(env)
	if err != nil {
		return nil
	}
	return &dpapi{files: *fs.(*files)}
}

func (d *dpapi) Kind() string { return KindDPAPI }

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func entropy(name string) *windows.DataBlob { return blob([]byte(Service + "/" + name)) }

func take(out *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
}

func (d *dpapi) Put(name string, secret []byte) error {
	if err := checkName(name); err != nil {
		return err
	}
	desc, _ := windows.UTF16PtrFromString("privometry-" + name)
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(secret), desc, entropy(name), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return fmt.Errorf("keystore: DPAPI: %w", err)
	}
	return d.files.Put(name, take(&out))
}

func (d *dpapi) Get(name string) ([]byte, error) {
	sealed, err := d.files.Get(name)
	if err != nil {
		return nil, err
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(sealed), nil, entropy(name), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("keystore: DPAPI could not open %s: %w", name, err)
	}
	return take(&out), nil
}

func (d *dpapi) Delete(name string) error { return d.files.Delete(name) }
