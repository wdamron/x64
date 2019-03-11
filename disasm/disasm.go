package disasm

import (
	"bytes"
	"fmt"
	"reflect"
	"unsafe"

	"golang.org/x/arch/x86/x86asm"
)

// Disassemble instructions from funcValue until while returns false. A maximum of 4096 bytes
// may be decoded. This function is entirely unsafe.
//
// funcValue must be a non-nil Go function-value.
//
// Some instructions supported by the instruction-encoder in the x64 package are not supported
// by the instruction-decoder in the x86asm package.
func Func(funcValue interface{}, while func(x86asm.Inst) bool) error {
	// See "Go 1.1 Function Calls":
	// https://docs.google.com/document/d/1bMwCey-gmqZVTpRax-ESeVuZGmjwbocYs1iHplK-cjo/pub
	type interfaceHeader struct {
		typ  uintptr
		addr **[]byte
	}
	v := reflect.ValueOf(funcValue)
	if !v.IsValid() || v.Kind() != reflect.Func || v.IsNil() {
		return fmt.Errorf("Argument for Disasm must a non-nil function-value")
	}
	header := *(*interfaceHeader)(unsafe.Pointer(&funcValue))
	code := (*[4096]byte)(unsafe.Pointer(*header.addr))
	n := 0
	for n < 4096 {
		inst, err := x86asm.Decode(code[n:n+17], 64)
		if err != nil {
			return err
		}
		if !while(inst) {
			return nil
		}
		if code[n] == 0xc3 { // find RET + padding (end of function)
			if n&15 != 0 {
				pad := 16 - (n & 15) // functions are typically aligned to a 16-byte boundary

				if bytes.Equal(code[n+1:n+1+pad], pad00[:pad]) || bytes.Equal(code[n+1:n+1+pad], padcc[:pad]) {
					return nil
				}
			} else {
				return nil
			}
		}
		n += inst.Len
	}
	return nil
}

// Manually allocated memory is typically zeroed
var pad00 = [...]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// The Go compiler seems to pad functions with 0xCC bytes to a 16-byte alignment boundary
var padcc = [...]byte{0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc}
