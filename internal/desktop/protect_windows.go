package desktop

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// protect encrypts data for the current Windows user (DPAPI): the app's key
// file is useless when copied to another account or computer.
func protect(b []byte) ([]byte, error) {
	return dpapi(b, true)
}

func unprotect(b []byte) ([]byte, error) {
	return dpapi(b, false)
}

func dpapi(b []byte, seal bool) ([]byte, error) {
	if len(b) == 0 {
		return nil, windows.ERROR_INVALID_DATA
	}
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	const uiForbidden = 0x1
	var err error
	if seal {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, uiForbidden, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, uiForbidden, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
