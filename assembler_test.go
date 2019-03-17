package x64

import (
	"fmt"
	"strings"
	"testing"
	"unsafe"

	. "github.com/wdamron/x64/feats"
	"golang.org/x/arch/x86/x86asm"
)

// Hard-coded instruction sequences are manually verified through the following tools:
//   * ODA: https://onlinedisassembler.com/odaweb/
//   * Shell-Storm: http://shell-storm.org/online/Online-Assembler-and-Disassembler/

func TestInstName(t *testing.T) {
	if ADC.Name() != "ADC" {
		t.Fatalf("ADC.Name() = %s", ADC.Name())
	}
	if MOV.Name() != "MOV" {
		t.Fatalf("MOV.Name() = %s", MOV.Name())
	}
	if VZEROUPPER.Name() != "VZEROUPPER" {
		t.Fatalf("VZEROUPPER.Name() = %s", VZEROUPPER.Name())
	}
}

func TestStaticDataSize(t *testing.T) {
	if unsafe.Sizeof(enc{}) != 16 {
		t.Fatalf("sizeof(enc) = %v", unsafe.Sizeof(enc{}))
	}
	size := len(encs) * int(unsafe.Sizeof(enc{}))
	// for each mnemonic: 4 bytes for the Inst + 2 bytes for the entry in instNameOffsets:
	size += len(instNameOffsets) * int(unsafe.Sizeof(ADD)+unsafe.Sizeof(instNameOffsets[0]))
	// packed string containing all instruction names:
	size += len(instNames)
	// for each arg-pattern: 8 bytes for the format + 1 byte for the argp constant:
	size += len(argpFormats) * int(unsafe.Sizeof(argpFormats[0])+unsafe.Sizeof(argp_))
	t.Logf("static data size %v", size)
	if size > 0xffff { // this can be revisited if the layout changes
		t.Fatalf("static data size exceeds %v", 0xfff)
	}
}

func TestEncode(t *testing.T) {
	asm := NewAssembler(make([]byte, 256))
	_expect := func(s string) {
		decoded, err := x86asm.Decode(asm.Code(), 64)
		if err != nil {
			t.Fatal(err)
		}
		intel := x86asm.IntelSyntax(decoded, 0, nil)
		if intel != s {
			t.Logf("encoded inst = %#x\n", asm.Code())
			t.Fatalf("decoded inst = %s != %s", intel, s)
		}
	}
	check := func(expect string, inst Inst, args ...Arg) {
		asm.Reset(nil)
		if err := asm.Inst(inst, args...); err != nil {
			t.Fatal(err)
		}
		_expect(expect)
	}
	checkregreg := func(expect string, inst Inst, dst, src Reg) {
		asm.Reset(nil)
		if err := asm.RR(inst, dst, src); err != nil {
			t.Fatal(err)
		}
		_expect(expect)
	}
	checkregmem := func(expect string, inst Inst, dst Reg, src Mem) {
		asm.Reset(nil)
		if err := asm.RM(inst, dst, src); err != nil {
			t.Fatal(err)
		}
		_expect(expect)
	}
	checkmemreg := func(expect string, inst Inst, dst Mem, src Reg) {
		asm.Reset(nil)
		if err := asm.MR(inst, dst, src); err != nil {
			t.Fatal(err)
		}
		_expect(expect)
	}
	checkregimm := func(expect string, inst Inst, dst Reg, imm ImmArg) {
		asm.Reset(nil)
		if err := asm.RI(inst, dst, imm); err != nil {
			t.Fatal(err)
		}
		_expect(expect)
	}
	checkmemimm := func(expect string, inst Inst, dst Mem, imm ImmArg) {
		asm.Reset(nil)
		if err := asm.MI(inst, dst, imm); err != nil {
			t.Fatal(err)
		}
		_expect(expect)
	}

	check("mov al, 0x1", MOV, AL, Imm8(1))
	checkregimm("mov al, 0x1", MOV, AL, Imm8(1))
	check("mov ah, 0x1", MOV, AH, Imm8(1))
	checkregimm("mov ah, 0x1", MOV, AH, Imm8(1))
	check("mov ax, 0x1", MOV, AX, Imm8(1)) // Imm8 will be auto-expanded to Imm16
	checkregimm("mov ax, 0x1", MOV, AX, Imm8(1))
	check("mov ax, 0x1", MOV, AX, Imm16(1))
	checkregimm("mov ax, 0x1", MOV, AX, Imm16(1))
	check("mov rax, 0x7fffffffffffffff", MOV, RAX, Imm64(0x7fffffffffffffff))
	checkregimm("mov rax, 0x7fffffffffffffff", MOV, RAX, Imm64(0x7fffffffffffffff))
	check("mov rax, r13", MOV, RAX, R13)
	checkregreg("mov rax, r13", MOV, RAX, R13)
	check("add rax, rbx", ADD, RAX, RBX)
	checkregreg("add rax, rbx", ADD, RAX, RBX)
	check("add rax, 0x1", ADD, RAX, Imm8(1))
	checkregimm("add rax, 0x1", ADD, RAX, Imm8(1))
	check("add qword ptr [rax], 0x1", ADD, Mem{Base: RAX}, Imm8(1))
	checkmemimm("add qword ptr [rax], 0x1", ADD, Mem{Base: RAX}, Imm8(1))
	check("xor rax, rbx", XOR, RAX, RBX)
	checkregreg("xor rax, rbx", XOR, RAX, RBX)
	check("pxor xmm1, xmm2", PXOR, X1, X2)
	checkregreg("pxor xmm1, xmm2", PXOR, X1, X2)
	check("mov rax, qword ptr [rbx]", MOV, RAX, Mem{Base: RBX})
	checkregmem("mov rax, qword ptr [rbx]", MOV, RAX, Mem{Base: RBX})
	check("mov qword ptr [rax], rbx", MOV, Mem{Base: RAX}, RBX)
	checkmemreg("mov qword ptr [rax], rbx", MOV, Mem{Base: RAX}, RBX)
	check("mov qword ptr [r13], rbx", MOV, Mem{Base: R13}, RBX)
	checkmemreg("mov qword ptr [r13], rbx", MOV, Mem{Base: R13}, RBX)
	check("mov rax, qword ptr [rbx+r15*1]", MOV, RAX, Mem{Base: RBX, Index: R15})
	checkregmem("mov rax, qword ptr [rbx+r15*1]", MOV, RAX, Mem{Base: RBX, Index: R15})
	check("mov rax, qword ptr [rbx+r15*2]", MOV, RAX, Mem{Base: RBX, Index: R15, Scale: 2})
	checkregmem("mov rax, qword ptr [rbx+r15*2]", MOV, RAX, Mem{Base: RBX, Index: R15, Scale: 2})
	check("mov rax, qword ptr [rbx+r15*2+0x8]", MOV, RAX, Mem{Base: RBX, Index: R15, Scale: 2, Disp: Rel8(8)})
	checkregmem("mov rax, qword ptr [rbx+r15*2+0x8]", MOV, RAX, Mem{Base: RBX, Index: R15, Scale: 2, Disp: Rel8(8)})
	check("mov rax, qword ptr [rbx+r15*2+0x8]", MOV, RAX, Mem{Base: RBX, Index: R15, Scale: 2, Disp: Rel32(8)})
	checkregmem("mov rax, qword ptr [rbx+r15*2+0x8]", MOV, RAX, Mem{Base: RBX, Index: R15, Scale: 2, Disp: Rel32(8)})
	check("lea rax, ptr [rbx+r15*2+0x8]", LEA, RAX, Mem{Base: RBX, Index: R15, Scale: 2, Disp: Rel8(8)})
	checkregmem("lea rax, ptr [rbx+r15*2+0x8]", LEA, RAX, Mem{Base: RBX, Index: R15, Scale: 2, Disp: Rel8(8)})
	check("lea rax, ptr [rbx+r15*2+0x8]", LEA, RAX, Mem{Base: RBX, Index: R15, Scale: 2, Disp: Rel32(8)})
	checkregmem("lea rax, ptr [rbx+r15*2+0x8]", LEA, RAX, Mem{Base: RBX, Index: R15, Scale: 2, Disp: Rel32(8)})
	check("jz .+0x4", JZ, Rel8(4))
	check("jz .-0x4", JZ, Rel8(-4))
	check("jz .+0x8000", JZ, Rel32(32768))
	check("jz .-0x8000", JZ, Rel32(-32768))
	check("jmp qword ptr [rax]", JMP, Mem{Base: RAX})
	check("lea rax, ptr [rip+0x10]", LEA, RAX, Mem{Base: RIP, Disp: Rel8(16)})
	checkregmem("lea rax, ptr [rip+0x10]", LEA, RAX, Mem{Base: RIP, Disp: Rel8(16)})

	asm.Reset(nil)
	if err := asm.Inst(VSHUFPD, X0, X1, Mem{Base: RBX, Width: 16}, Imm8(2)); err != nil {
		t.Logf("vshufpd xmm0, xmm1, xmmword ptr [rbx], 0x2 = %#x", asm.Code())
		t.Fatal(err)
	}
	if fmt.Sprintf("%#x", asm.Code()) != "0xc5f1c60302" {
		t.Fatalf("vshufpd xmm0, xmm1, xmmword ptr [rbx], 0x2 = %#x != 0xc5f1c60302", asm.Code())
	}

	// VSIB addressing:

	asm.Reset(nil)
	if err := asm.Inst(VGATHERDPS, X0, Mem{Base: RDX, Index: X1}, X2); err != nil {
		t.Logf("vgatherdps xmm0, [rdx+xmm1], xmm2 = %#x", asm.Code())
		t.Fatal(err)
	}
	if fmt.Sprintf("%#x", asm.Code()) != "0xc4e26992440a00" {
		t.Fatalf("vgatherdps xmm0, [rdx+xmm1], xmm2 = %#x != 0xc4e26992440a00", asm.Code())
	}

	asm.Reset(nil)
	if err := asm.Inst(VGATHERQPS, X0, Mem{Base: RDX, Index: X1, Disp: Rel8(64), Scale: 4}, X2); err != nil {
		t.Logf("vgatherqps xmm0, [rdx+xmm1*4+0x40], xmm2 = %#x", asm.Code())
		t.Fatal(err)
	}
	if fmt.Sprintf("%#x", asm.Code()) != "0xc4e26993448a40" {
		t.Fatalf("vgatherqps xmm0, [rdx+xmm1*4+0x40], xmm2 = %#x != 0xc4e26993448a40", asm.Code())
	}

	// With CPU features disabled:

	if err := asm.Inst(VSHUFPD, X0, X1, X3, Imm8(1)); err != nil {
		t.Fatal(err)
	}
	asm.DisableFeature(AVX)
	if err := asm.Inst(VSHUFPD, X0, X1, X3, Imm8(1)); err != ErrNoMatch {
		t.Fatalf("Expected no matching instruction for VSHUFPD with AVX disabled")
	}
}

func TestAlignPC(t *testing.T) {
	asm := NewAssembler(make([]byte, 256))
	asm.Inst(MOV, RAX, RBX)
	asm.AlignPC(16)
	if len(asm.Code()) != 16 {
		t.Fatalf("len(code) = %d", len(asm.Code()))
	}
	// decode mov
	decoded, err := x86asm.Decode(asm.Code(), 64)
	if err != nil {
		t.Fatal(err)
	}
	intel := x86asm.IntelSyntax(decoded, 0, nil)
	if intel != "mov rax, rbx" {
		t.Logf("encoded inst = %#x\n", asm.Code())
		t.Fatalf("decoded inst = %s != mov rax, rbx", intel)
	}
	// decode nops
	for i := decoded.Len; i > 0; i -= decoded.Len {
		decoded, err = x86asm.Decode(asm.Code()[decoded.Len:], 64)
		if err != nil {
			t.Fatal(err)
		}
		intel = x86asm.IntelSyntax(decoded, 0, nil)
		if !strings.HasPrefix(intel, "nop") {
			t.Logf("encoded inst = %#x\n", asm.Code())
			t.Fatalf("decoded inst = %s != nop ...", intel)
		}
	}
}

func TestRelocs(t *testing.T) {
	asm := NewAssembler(make([]byte, 256))

	// 8-bit displacements
	label := asm.NewLabel()
	asm.Inst(MOV, RAX, RBX)
	asm.Inst(ADD, RAX, Imm8(5))
	label2 := asm.NewLabel()
	asm.Inst(ADD, RBX, Imm8(1))
	asm.Inst(JMP, label.Rel8())
	label3 := asm.NewLabel()
	asm.Inst(ADD, RBX, Imm8(1))
	asm.Inst(JMP, label2.Rel8())
	asm.Inst(JMP, label3.Rel8())
	if err := asm.Finalize(); err != nil {
		t.Fatal(err)
	}
	t.Logf("%#x", asm.Code())
	if fmt.Sprintf("%#x", asm.Code()) != "0x4889d84883c0054883c301ebf34883c301ebf4ebf8" {
		t.Fatalf("encoded = %#x != %s", asm.Code(), "0x4889d84883c0054883c301ebf34883c301ebf4ebf8")
	}
	// 32-bit displacement
	asm.Reset(nil)
	label = asm.NewLabel()
	asm.Inst(MOV, RAX, RBX)
	asm.Inst(ADD, RAX, Imm8(5))
	_ = asm.NewLabel()
	asm.Inst(ADD, RBX, Imm8(1))
	asm.Inst(JMP, label.Rel32())
	if err := asm.Finalize(); err != nil {
		t.Fatal(err)
	}
	t.Logf("%#x", asm.Code())
	if fmt.Sprintf("%#x", asm.Code()) != "0x4889d84883c0054883c301e9f0ffffff" {
		t.Fatalf("encoded = %#x != %s", asm.Code(), "0x4889d84883c0054883c301e9f0ffffff")
	}
	// auto 32-bit displacement
	asm.Reset(nil)
	label = asm.NewLabel()
	asm.Inst(MOV, RAX, RBX)
	asm.Inst(ADD, RAX, Imm8(5))
	_ = asm.NewLabel()
	asm.Inst(ADD, RBX, Imm8(1))
	asm.Inst(JMP, label)
	if err := asm.Finalize(); err != nil {
		t.Fatal(err)
	}
	t.Logf("%#x", asm.Code())
	if fmt.Sprintf("%#x", asm.Code()) != "0x4889d84883c0054883c301e9f0ffffff" {
		t.Fatalf("encoded = %#x != %s", asm.Code(), "0x4889d84883c0054883c301e9f0ffffff")
	}

	// label reference with additional 8-bit displacement
	asm.Reset(nil)
	label = asm.NewLabel()
	asm.Inst(MOV, RAX, RBX)
	asm.Inst(ADD, RAX, Imm8(5))
	delta := asm.PC()
	asm.Inst(ADD, RBX, Imm8(1))
	asm.Inst(JMP, label.Disp8(int8(delta))) // jump to middle of block
	if err := asm.Finalize(); err != nil {
		t.Fatal(err)
	}
	t.Logf("%#x", asm.Code())
	if fmt.Sprintf("%#x", asm.Code()) != "0x4889d84883c0054883c301ebfa" {
		t.Fatalf("encoded = %#x != %s", asm.Code(), "0x4889d84883c0054883c301ebfa")
	}
	// label reference with additional 32-bit displacement
	asm.Reset(nil)
	label = asm.NewLabel()
	asm.Inst(MOV, RAX, RBX)
	asm.Inst(ADD, RAX, Imm8(5))
	delta = asm.PC()
	asm.Inst(ADD, RBX, Imm8(1))
	asm.Inst(JMP, label.Disp32(int32(delta))) // jump to middle of block
	if err := asm.Finalize(); err != nil {
		t.Fatal(err)
	}
	t.Logf("%#x", asm.Code())
	if fmt.Sprintf("%#x", asm.Code()) != "0x4889d84883c0054883c301e9f7ffffff" {
		t.Fatalf("encoded = %#x != %s", asm.Code(), "0x4889d84883c0054883c301e9f7ffffff")
	}
	// label reference with RIP-relative addressing
	asm.Reset(nil)
	label = asm.NewLabel()
	asm.Inst(MOV, RAX, RBX)
	delta = asm.PC()
	asm.Inst(MOV, RBX, RAX)
	if err := asm.Inst(LEA, RAX, Mem{Base: RIP, Disp: label.Disp32(int32(delta))}); err != nil { // jump to middle of block
		t.Fatal(err)
	}
	if err := asm.Finalize(); err != nil {
		t.Fatal(err)
	}
	t.Logf("%#x", asm.Code())
	if fmt.Sprintf("%#x", asm.Code()) != "0x4889d84889c3488d05f6ffffff" {
		t.Fatalf("encoded = %#x != %s", asm.Code(), "0x4889d84889c3488d05f6ffffff")
	}
}
