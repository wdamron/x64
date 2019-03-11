// package disasm provides disassembly for Go functions at runtime.
//
// example usage:
//
// 	package example
//
// 	import (
// 		"fmt"
// 		"os"
//
// 		// importing everything from the package into the current scope makes for less noise
// 		. "github.com/wdamron/x64"
// 		"github.com/wdamron/x64/disasm"
// 		"golang.org/x/arch/x86/x86asm"
// 		"golang.org/x/sys/unix"
// 	)
//
// 	const (
// 		ANON_PRIVATE = unix.MAP_ANON|unix.MAP_PRIVATE
//
// 		READ_WRITE = unix.PROT_READ|unix.PROT_WRITE
// 		READ_EXEC  = unix.PROT_READ|unix.PROT_EXEC
// 	)
//
// 	func Useless() error {
// 		mem, err := unix.Mmap(-1, 0, os.Getpagesize(), READ_WRITE, ANON_PRIVATE)
// 		if err != nil {
// 			return fmt.Errorf("sys/unix.Mmap failed: %v", err)
// 		}
//
// 		defer unix.Munmap(mem)
//
// 		// Assemble a new function (see the x64 package):
//
// 		asm := NewAssembler(mem)
// 		sum := (func(a, b int) int)(nil) // placeholder value
//
// 		// Note: the call frame (arguments and returned value) starts at [RSP+8]
//
// 		asm.Inst(MOV, RAX, Mem{Base: RSP, Disp: Rel8(8)})   // RAX := a+0(FP)
// 		asm.Inst(MOV, RBX, Mem{Base: RSP, Disp: Rel8(16)})  // RBX := b+8(FP)
// 		asm.Inst(ADD, RAX, RBX)                             // RAX += RBX
// 		asm.Inst(MOV, Mem{Base: RSP, Disp: Rel8(24)}, RAX)  // ret+16(FP) := RAX
// 		asm.Inst(RET)                                       // return
// 		if asm.Err() != nil {
// 			return asm.Err()
// 		}
//
// 		if err := unix.Mprotect(mem, READ_EXEC); err != nil {
// 			return fmt.Errorf("sys/unix.Mprotect failed: %v", err)
// 		}
//
// 		// Assign the address of the assembled/executable code to the code-pointer within
// 		// the placeholder function-value:
// 		if err := SetFunctionCode(&sum, mem); err != nil {
// 			return err
// 		}
//
// 		if sum(1, 2) != 3 {
// 			return fmt.Errorf("sum(1, 2) should not equal %v", sum(1, 2))
// 		}
//
// 		// Disassemble the function:
//
// 		insts := make([]x86asm.Inst, 0, 5)
// 		takeWhile := func(inst x86asm.Inst) bool {
// 			insts = append(insts, inst)
// 			return inst.Op != x86asm.RET
// 		}
// 		if err := disasm.Func(sum, takeWhile); err != nil {
// 			return err
// 		}
//
// 		for _, inst := range insts {
// 			fmt.Println(x86asm.IntelSyntax(inst, 0, nil))
// 		}
// 		// Outputs:
// 		//
// 		// 	mov rax, qword ptr [rsp+0x8]
// 		// 	mov rbx, qword ptr [rsp+0x10]
// 		// 	add rax, rbx
// 		// 	mov qword ptr [rsp+0x18], rax
// 		// 	ret
//
// 		return nil
// 	}
package disasm
