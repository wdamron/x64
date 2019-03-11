package disasm

import (
	"os"
	"testing"

	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"

	. "github.com/wdamron/x64"
)

func TestDisasm(t *testing.T) {
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

	if sum(1, 2) != 3 {
		t.Fatalf("sum(1, 2) should not equal %v", sum(1, 2))
	}

	var insts []x86asm.Inst
	takeWhile := func(inst x86asm.Inst) bool {
		insts = append(insts, inst)
		return true // RET + padding should be automatically detected
	}
	if err := Func(sum, takeWhile); err != nil {
		t.Fatal(err)
	}
	if len(insts) != 5 {
		t.Fatalf("expected %v instructions, found %v", 5, len(insts))
	}
	check := func(expect string, inst x86asm.Inst) {
		intel := x86asm.IntelSyntax(inst, 0, nil)
		if intel != expect {
			t.Fatalf("Expected instruction: %s --- found %s", expect, intel)
		}
	}
	check("mov rax, qword ptr [rsp+0x8]", insts[0])
	check("mov rbx, qword ptr [rsp+0x10]", insts[1])
	check("add rax, rbx", insts[2])
	check("mov qword ptr [rsp+0x18], rax", insts[3])
	check("ret", insts[4])

}
