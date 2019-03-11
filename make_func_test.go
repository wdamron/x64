package x64

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSetFunctionCode(t *testing.T) {
	mem, err := unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("sys/unix.Mmap failed: %v", err)
	}

	defer unix.Munmap(mem)

	// The frame (args + return) starts at [RSP+8]
	asm := NewAssembler(mem)
	asm.Inst(MOV, RAX, Mem{Base: RSP, Disp: Rel8(8)})
	asm.Inst(MOV, RBX, Mem{Base: RSP, Disp: Rel8(16)})
	asm.Inst(ADD, RAX, RBX)
	asm.Inst(MOV, Mem{Base: RSP, Disp: Rel8(24)}, RAX)
	asm.Inst(RET)
	if asm.Err() != nil {
		t.Fatal(err)
	}

	if err := unix.Mprotect(mem, unix.PROT_READ|unix.PROT_EXEC); err != nil {
		t.Fatalf("sys/unix.Mprotect failed: %v", err)
	}

	sum := (func(a, b int) int)(nil)
	if err := SetFunctionCode(&sum, mem); err != nil {
		t.Fatal(err)
	}

	for i := -5; i <= 5; i++ {
		for j := -5; j <= 5; j++ {
			s := sum(i, j)
			if s != i+j {
				t.Fatalf("sum(%v, %v) = %v", i, j, s)
			}
		}
	}
}
