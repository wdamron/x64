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
	check("mov eax, 0x7fffffff", MOV, EAX, Imm32(0x7fffffff))
	checkregimm("mov eax, 0x7fffffff", MOV, EAX, Imm32(0x7fffffff))
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

	check("movzx rax, byte ptr [rbx]", MOVZX, RAX, Mem{Base: RBX, Width: 1})
	checkregmem("movzx rax, byte ptr [rbx]", MOVZX, RAX, Mem{Base: RBX, Width: 1})
	check("movzx rax, word ptr [rbx]", MOVZX, RAX, Mem{Base: RBX, Width: 2})
	checkregmem("movzx rax, word ptr [rbx]", MOVZX, RAX, Mem{Base: RBX, Width: 2})

	check("movsx rax, byte ptr [rbx]", MOVSX, RAX, Mem{Base: RBX, Width: 1})
	checkregmem("movsx rax, byte ptr [rbx]", MOVSX, RAX, Mem{Base: RBX, Width: 1})
	check("movsx rax, word ptr [rbx]", MOVSX, RAX, Mem{Base: RBX, Width: 2})
	checkregmem("movsx rax, word ptr [rbx]", MOVSX, RAX, Mem{Base: RBX, Width: 2})
	check("movsxd rax, dword ptr [rbx]", MOVSX, RAX, Mem{Base: RBX, Width: 4})
	checkregmem("movsxd rax, dword ptr [rbx]", MOVSX, RAX, Mem{Base: RBX, Width: 4})
	check("movsxd rax, dword ptr [rbx]", MOVSXD, RAX, Mem{Base: RBX, Width: 4})
	checkregmem("movsxd rax, dword ptr [rbx]", MOVSXD, RAX, Mem{Base: RBX, Width: 4})

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

	// From previously matched:

	matcher := NewInstMatcher()
	asm.Reset(nil)
	if err := matcher.Match(ADD, RAX, RBX); err != nil {
		t.Fatal(err)
	}
	if err := asm.InstFrom(matcher); err != nil {
		t.Fatal(err)
	}
	_expect("add rax, rbx")
	// re-use matched instruction:
	asm.Reset(nil)
	if err := asm.InstFrom(matcher); err != nil {
		t.Fatal(err)
	}
	_expect("add rax, rbx")
	// re-use matcher:
	asm.Reset(nil)
	if err := matcher.Match(ADD, RBX, RAX); err != nil {
		t.Fatal(err)
	}
	if err := asm.InstFrom(matcher); err != nil {
		t.Fatal(err)
	}
	_expect("add rbx, rax")
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

func TestAllMatches(t *testing.T) {
	m := NewInstMatcher()
	expect := func(count int, inst Inst, args ...Arg) {
		matches, err := m.AllMatches(inst, args...)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != count {
			t.Fatalf("Expected %v match(es), found %v", count, len(matches))
		}
	}
	expect(2, ADD, RAX, RBX)            // r0r0, r0v0
	expect(2, ADD, RAX, Imm64(1))       // A0i0, r0i0
	expect(2, ADD, AL, Imm8(1))         // Abib, rbib
	expect(1, ADD, RAX, Mem{Base: RBX}) // r0v0
}

func TestBasicInstructionSet(t *testing.T) {
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
			t.Fatal(expect, "--", err)
		}
		_expect(expect)
	}

	check("push rax", PUSH, RAX)
	check("push r9", PUSH, R9)
	check("pop rax", POP, RAX)
	check("pop r9", POP, R9)
	check("inc rax", INC, RAX)
	check("dec rax", DEC, RAX)
	check("add rax, rbx", ADD, RAX, RBX)
	check("sub rax, rbx", SUB, RAX, RBX)
	check("mul rbx", MUL, RBX)   // unsigned
	check("imul rbx", IMUL, RBX) // signed
	check("div rbx", DIV, RBX)   // unsigned
	check("idiv rbx", IDIV, RBX) // signed
	check("and rax, rbx", AND, RAX, RBX)
	check("or rax, rbx", OR, RAX, RBX)
	check("xor rax, rbx", XOR, RAX, RBX)
	check("neg rax", NEG, RAX)               // two's complement negation
	check("not rax", NOT, RAX)               // one's complement negation
	check("shl rax, 0x3", SHL, RAX, Imm8(3)) // logical shift
	check("shr rax, 0x3", SHR, RAX, Imm8(3)) // logical shift
	check("sar rax, 0x3", SAR, RAX, Imm8(3)) // arithmetic shift
	check("rol rax, 0x3", ROL, RAX, Imm8(3))
	check("ror rax, 0x3", ROR, RAX, Imm8(3))
	check("cmp rax, 0x1", CMP, RAX, Imm8(1))
	check("cmp rax, rbx", CMP, RAX, RBX)
	check("cmp qword ptr [rbx], rax", CMP, Mem{Base: RBX}, RAX)
	check("cmp rax, qword ptr [rbx]", CMP, RAX, Mem{Base: RBX})
	check("test rax, 0x1", TEST, RAX, Imm64(1))
	check("test rax, rbx", TEST, RAX, RBX)
	check("test qword ptr [rbx], rax", TEST, Mem{Base: RBX}, RAX)
	check("test qword ptr [rbx], rax", TEST, RAX, Mem{Base: RBX}) // same encoding as above

	check("add rax, qword ptr [rbx]", ADD, RAX, Mem{Base: RBX})
	check("sub rax, qword ptr [rbx]", SUB, RAX, Mem{Base: RBX})
	check("mul qword ptr [rbx]", MUL, Mem{Base: RBX})
	check("imul qword ptr [rbx]", IMUL, Mem{Base: RBX})
	check("div qword ptr [rbx]", DIV, Mem{Base: RBX})
	check("idiv qword ptr [rbx]", IDIV, Mem{Base: RBX})
	check("and rax, qword ptr [rbx]", AND, RAX, Mem{Base: RBX})
	check("or rax, qword ptr [rbx]", OR, RAX, Mem{Base: RBX})
	check("xor rax, qword ptr [rbx]", XOR, RAX, Mem{Base: RBX})

	check("mov rax, qword ptr [rbx]", MOV, RAX, Mem{Base: RBX})
	check("mov qword ptr [rax], rbx", MOV, Mem{Base: RAX}, RBX)
	check("mov rax, qword ptr [rbx+rcx*1]", MOV, RAX, Mem{Base: RBX, Index: RCX})
	check("mov rax, qword ptr [rbx+rcx*2]", MOV, RAX, Mem{Base: RBX, Index: RCX, Scale: 2})
	check("mov rax, qword ptr [rbx+rcx*2+0x8]", MOV, RAX, Mem{Base: RBX, Index: RCX, Scale: 2, Disp: Rel8(8)})
	check("movzx rax, byte ptr [rbx]", MOVZX, RAX, Mem{Base: RBX, Width: 1})
	check("movzx rax, word ptr [rbx]", MOVZX, RAX, Mem{Base: RBX, Width: 2})
	check("movsx rax, byte ptr [rbx]", MOVSX, RAX, Mem{Base: RBX, Width: 1})
	check("movsx rax, word ptr [rbx]", MOVSX, RAX, Mem{Base: RBX, Width: 2})
	check("movsxd rax, dword ptr [rbx]", MOVSX, RAX, Mem{Base: RBX, Width: 4})
	check("movsxd rax, dword ptr [rbx]", MOVSXD, RAX, Mem{Base: RBX, Width: 4})
	check("movdqa xmm0, xmmword ptr [rdi]", MOVDQA, X0, Mem{Base: RDI, Width: 16})
	check("movdqa xmmword ptr [rdi], xmm0", MOVDQA, Mem{Base: RDI, Width: 16}, X0)
	check("movdqu xmm0, xmmword ptr [rdi]", MOVDQU, X0, Mem{Base: RDI, Width: 16})
	check("movdqu xmmword ptr [rdi], xmm0", MOVDQU, Mem{Base: RDI, Width: 16}, X0)
}

func TestConditionCodes(t *testing.T) {
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
			t.Fatal(expect, "--", err)
		}
		_expect(expect)
	}

	check("jb .+0x4", JB, Rel8(4))     // unsigned less-than
	check("jnb .+0x4", JAE, Rel8(4))   // unsigned greater-than or equal
	check("jnb .+0x4", JNB, Rel8(4))   // unsigned greater-than or equal
	check("jz .+0x4", JE, Rel8(4))     // equal
	check("jz .+0x4", JZ, Rel8(4))     // equal
	check("jnz .+0x4", JNE, Rel8(4))   // not-equal
	check("jnz .+0x4", JNZ, Rel8(4))   // not-equal
	check("jbe .+0x4", JBE, Rel8(4))   // unsigned less-than or equal
	check("jnbe .+0x4", JA, Rel8(4))   // unsigned greater-than
	check("jnbe .+0x4", JNBE, Rel8(4)) // unsigned greater-than
	check("jl .+0x4", JL, Rel8(4))     // signed less-than
	check("jnl .+0x4", JGE, Rel8(4))   // signed greater-than or equal
	check("jnl .+0x4", JNL, Rel8(4))   // signed greater-than or equal
	check("jle .+0x4", JLE, Rel8(4))   // signed less-than or equal
	check("jnle .+0x4", JG, Rel8(4))   // signed greater-than
	check("jnle .+0x4", JNLE, Rel8(4)) // signed greater-than

	check("setb al", SETB, AL)     // unsigned less-than
	check("setnb al", SETAE, AL)   // unsigned greater-than or equal
	check("setnb al", SETNB, AL)   // unsigned greater-than or equal
	check("setz al", SETE, AL)     // equal
	check("setz al", SETZ, AL)     // equal
	check("setnz al", SETNE, AL)   // not-equal
	check("setnz al", SETNZ, AL)   // not-equal
	check("setbe al", SETBE, AL)   // unsigned less-than or equal
	check("setnbe al", SETA, AL)   // unsigned greater-than
	check("setnbe al", SETNBE, AL) // unsigned greater-than
	check("setl al", SETL, AL)     // signed less-than
	check("setnl al", SETGE, AL)   // signed greater-than or equal
	check("setnl al", SETNL, AL)   // signed greater-than or equal
	check("setle al", SETLE, AL)   // signed less-than or equal
	check("setnle al", SETG, AL)   // signed greater-than
	check("setnle al", SETNLE, AL) // signed greater-than

	check("cmovb rax, rbx", CMOVB, RAX, RBX)     // unsigned less-than
	check("cmovnb rax, rbx", CMOVAE, RAX, RBX)   // unsigned greater-than or equal
	check("cmovnb rax, rbx", CMOVNB, RAX, RBX)   // unsigned greater-than or equal
	check("cmovz rax, rbx", CMOVE, RAX, RBX)     // equal
	check("cmovz rax, rbx", CMOVZ, RAX, RBX)     // equal
	check("cmovnz rax, rbx", CMOVNE, RAX, RBX)   // not-equal
	check("cmovnz rax, rbx", CMOVNZ, RAX, RBX)   // not-equal
	check("cmovbe rax, rbx", CMOVBE, RAX, RBX)   // unsigned less-than or equal
	check("cmovnbe rax, rbx", CMOVA, RAX, RBX)   // unsigned greater-than
	check("cmovnbe rax, rbx", CMOVNBE, RAX, RBX) // unsigned greater-than
	check("cmovl rax, rbx", CMOVL, RAX, RBX)     // signed less-than
	check("cmovnl rax, rbx", CMOVGE, RAX, RBX)   // signed greater-than or equal
	check("cmovnl rax, rbx", CMOVNL, RAX, RBX)   // signed greater-than or equal
	check("cmovle rax, rbx", CMOVLE, RAX, RBX)   // signed less-than or equal
	check("cmovnle rax, rbx", CMOVG, RAX, RBX)   // signed greater-than
	check("cmovnle rax, rbx", CMOVNLE, RAX, RBX) // signed greater-than

	check("jb .+0x4", Jcc(CCUnsignedLT), Rel8(4))
	check("jnb .+0x4", Jcc(CCUnsignedGTE), Rel8(4))
	check("jz .+0x4", Jcc(CCEq), Rel8(4))
	check("jnz .+0x4", Jcc(CCNeq), Rel8(4))
	check("jbe .+0x4", Jcc(CCUnsignedLTE), Rel8(4))
	check("jnbe .+0x4", Jcc(CCUnsignedGT), Rel8(4))
	check("jl .+0x4", Jcc(CCSignedLT), Rel8(4))
	check("jnl .+0x4", Jcc(CCSignedGTE), Rel8(4))
	check("jle .+0x4", Jcc(CCSignedLTE), Rel8(4))
	check("jnle .+0x4", Jcc(CCSignedGT), Rel8(4))

	check("setb al", Setcc(CCUnsignedLT), AL)
	check("setnb al", Setcc(CCUnsignedGTE), AL)
	check("setz al", Setcc(CCEq), AL)
	check("setnz al", Setcc(CCNeq), AL)
	check("setbe al", Setcc(CCUnsignedLTE), AL)
	check("setnbe al", Setcc(CCUnsignedGT), AL)
	check("setl al", Setcc(CCSignedLT), AL)
	check("setnl al", Setcc(CCSignedGTE), AL)
	check("setle al", Setcc(CCSignedLTE), AL)
	check("setnle al", Setcc(CCSignedGT), AL)

	check("cmovb rax, rbx", Cmovcc(CCUnsignedLT), RAX, RBX)
	check("cmovnb rax, rbx", Cmovcc(CCUnsignedGTE), RAX, RBX)
	check("cmovz rax, rbx", Cmovcc(CCEq), RAX, RBX)
	check("cmovnz rax, rbx", Cmovcc(CCNeq), RAX, RBX)
	check("cmovbe rax, rbx", Cmovcc(CCUnsignedLTE), RAX, RBX)
	check("cmovnbe rax, rbx", Cmovcc(CCUnsignedGT), RAX, RBX)
	check("cmovl rax, rbx", Cmovcc(CCSignedLT), RAX, RBX)
	check("cmovnl rax, rbx", Cmovcc(CCSignedGTE), RAX, RBX)
	check("cmovle rax, rbx", Cmovcc(CCSignedLTE), RAX, RBX)
	check("cmovnle rax, rbx", Cmovcc(CCSignedGT), RAX, RBX)
}

func TestPrefixes(t *testing.T) {
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
	checkLock := func(expect string, inst Inst, args ...Arg) {
		asm.Reset(nil)
		if err := asm.Lock(inst, args...); err != nil {
			t.Fatal(expect, "--", err)
		}
		_expect(expect)
	}
	checkRep := func(expect string, inst Inst, args ...Arg) {
		asm.Reset(nil)
		if err := asm.Rep(inst, args...); err != nil {
			t.Fatal(expect, "--", err)
		}
		_expect(expect)
	}
	checkRepne := func(expect string, inst Inst, args ...Arg) {
		asm.Reset(nil)
		if err := asm.Repne(inst, args...); err != nil {
			t.Fatal(expect, "--", err)
		}
		_expect(expect)
	}

	checkLock("lock add qword ptr [rdi], rax", ADD, Mem{Base: RDI}, RAX)
	checkRep("rep stosq qword ptr [rdi]", STOSQ)
	checkRep("rep scasq qword ptr [rdi]", SCASQ)
	checkRepne("repne scasq qword ptr [rdi]", SCASQ)
}
