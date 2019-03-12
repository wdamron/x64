# x64

x86-64 instruction encoder in Go (work in progress)

This package contains a more-or-less direct port of the instruction-encoding logic from [CensoredUsername/dynasm-rs](https://github.com/CensoredUsername/dynasm-rs). Only a relatively small subset of the features in `dynasm-rs` are supported. Not many features are working or tested yet, but the intended use-case is assembling executable code at runtime.

See the [godocs](https://godoc.org/github.com/wdamron/x64) or otherwise look at the tests for usage examples.

## "Basic" Usage

```go
package example

import (
	"fmt"
	"os"

	// importing everything from the package into the current scope makes for less noise
	. "github.com/wdamron/x64"
	"golang.org/x/sys/unix"
)

const (
	ANON_PRIVATE = unix.MAP_ANON|unix.MAP_PRIVATE

	READ_WRITE = unix.PROT_READ|unix.PROT_WRITE
	READ_EXEC  = unix.PROT_READ|unix.PROT_EXEC
)

func CompileSumFunc() (func(a, b int) int, error) {
	mem, err := unix.Mmap(-1, 0, os.Getpagesize(), READ_WRITE, ANON_PRIVATE)
	if err != nil {
		return nil, fmt.Errorf("sys/unix.Mmap failed: %v", err)
	}

	asm := NewAssembler(mem)

	// Note: the call frame (arguments and returned value) starts at [RSP+8].
	// The return address will be stored at [RSP].

	asm.Inst(MOV, RAX, Mem{Base: RSP, Disp: Rel8(8)})   // RAX := a+0(FP)
	asm.Inst(MOV, RBX, Mem{Base: RSP, Disp: Rel8(16)})  // RBX := b+8(FP)
	asm.Inst(ADD, RAX, RBX)                             // RAX += RBX
	asm.Inst(MOV, Mem{Base: RSP, Disp: Rel8(24)}, RAX)  // ret+16(FP) := RAX
	asm.Inst(RET)                                       // return
	if asm.Err() != nil {
		_ = unix.Munmap(mem)
		return nil, asm.Err()
	}

	if err := unix.Mprotect(mem, READ_EXEC); err != nil {
		_ = unix.Munmap(mem)
		return nil, fmt.Errorf("sys/unix.Mprotect failed: %v", err)
	}

	sum := (func(a, b int) int)(nil) // placeholder value

	// Assign the address of the assembled/executable code to the code-pointer within
	// the placeholder function-value:
	if err := SetFunctionCode(&sum, mem); err != nil {
		_ = unix.Munmap(mem)
		return nil, err
	}

	return sum, nil
}

```
