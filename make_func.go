package x64

import (
	"fmt"
	"reflect"

	"unsafe"
)

// Set the executable code for dstAddr. This function is entirely unsafe.
//
// dstAddr must be a pointer to a function value.
// executable must be marked with PROT_EXEC privileges through a MPROTECT system-call.
func SetFunctionCode(dstAddr interface{}, executable []byte) error {
	// See "Go 1.1 Function Calls":
	// https://docs.google.com/document/d/1bMwCey-gmqZVTpRax-ESeVuZGmjwbocYs1iHplK-cjo/pub
	type interfaceHeader struct {
		typ  uintptr
		addr **[]byte
	}
	v := reflect.ValueOf(dstAddr)
	if !v.IsValid() || v.Kind() != reflect.Ptr || v.IsNil() || !v.Elem().CanSet() || v.Elem().Kind() != reflect.Func {
		return fmt.Errorf("Destination for SetFunctionCode must be a pointer to a function-value")
	}
	header := *(*interfaceHeader)(unsafe.Pointer(&dstAddr))
	*header.addr = &executable
	return nil
}
