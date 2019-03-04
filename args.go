package x64

// Arg represents an instruction argument.
type Arg interface {
	isArg()
	width() uint8
}

// Mem is a memory-reference argument. Base (or Index) may be RIP for RIP-relative addressing.
//
// Mem implements Arg.
type Mem struct {
	Disp  DispArg
	Base  Reg
	Index Reg
	_     uint32
	_     uint16
	Scale uint8
	Width uint8
}

func (m Mem) isArg()       {}
func (m Mem) width() uint8 { return m.Width }

// ImmArg represents an immediate argument.
//
// Any Imm8, Imm16, Imm32, or Imm64 value implements ImmArg.
type ImmArg interface {
	Arg
	isImm()
	Int64() int64
}

func isImm(arg Arg) bool {
	_, ok := arg.(ImmArg)
	return ok
}

// Imm8 is an 8-bit immediate argument.
//
// Imm8 implements ImmArg.
type Imm8 int8

// Imm16 is a 16-bit immediate argument.
//
// Imm16 implements ImmArg.
type Imm16 int16

// Imm32 is a 32-bit immediate argument.
//
// Imm32 implements ImmArg.
type Imm32 int32

// Imm64 is a 64-bit immediate argument.
//
// Imm64 implements ImmArg.
type Imm64 int64

func (i Imm8) isArg()  {}
func (i Imm16) isArg() {}
func (i Imm32) isArg() {}
func (i Imm64) isArg() {}

func (i Imm8) isImm()  {}
func (i Imm16) isImm() {}
func (i Imm32) isImm() {}
func (i Imm64) isImm() {}

func (i Imm8) width() uint8  { return 1 }
func (i Imm16) width() uint8 { return 2 }
func (i Imm32) width() uint8 { return 4 }
func (i Imm64) width() uint8 { return 8 }

func (i Imm8) Int64() int64  { return int64(i) }
func (i Imm16) Int64() int64 { return int64(i) }
func (i Imm32) Int64() int64 { return int64(i) }
func (i Imm64) Int64() int64 { return int64(i) }

// DispArg represents a label reference (with or without additional displacement) or a relative displacement.
//
// Any Rel8, Rel16, Rel32, Label, Label8, Label16, Label32, or LabelDisp value implements DispArg.
type DispArg interface {
	Arg
	isDisp()
	Int32() int32
}

func isDisp(arg Arg) bool {
	_, ok := arg.(DispArg)
	return ok
}

// RelArg represents a relative displacement.
type RelArg interface {
	DispArg
	isRel()
}

func isRel(arg Arg) bool {
	_, ok := arg.(RelArg)
	return ok
}

// Rel8 is an 8-bit displacement argument.
//
// Rel8 implements DispArg.
type Rel8 int8

// Rel16 is a 16-bit displacement argument.
//
// Rel16 implements DispArg.
type Rel16 int16

// Rel32 is a 32-bit displacement argument.
//
// Rel32 implements DispArg.
type Rel32 int32

func (r Rel8) isArg()  {}
func (r Rel16) isArg() {}
func (r Rel32) isArg() {}

func (r Rel8) isDisp()  {}
func (r Rel16) isDisp() {}
func (r Rel32) isDisp() {}

func (r Rel8) isRel()  {}
func (r Rel16) isRel() {}
func (r Rel32) isRel() {}

func (r Rel8) width() uint8  { return 1 }
func (r Rel16) width() uint8 { return 2 }
func (r Rel32) width() uint8 { return 4 }

func (r Rel8) Int32() int32  { return int32(r) }
func (r Rel16) Int32() int32 { return int32(r) }
func (r Rel32) Int32() int32 { return int32(r) }

// LabelArg represents a label reference, with or without additional displacement.
//
// Any Label, Label8, Label16, Label32, or LabelDisp value implements LabelArg and DispArg.
type LabelArg interface {
	DispArg
	isLabel()
	label() uint16
}

var _ LabelArg = Label{}
var _ LabelArg = LabelDisp{}
var _ LabelArg = Label8(0)
var _ LabelArg = Label16(0)
var _ LabelArg = Label32(0)

func isLabel(arg Arg) bool {
	_, ok := arg.(LabelArg)
	return ok
}

// Label is a reference to a label.
type Label struct {
	pc uint32 // offset/PC
	id uint16 // auto-incrementing identifier
	_  uint16
}

// LabelDisp is a reference to a label with additional displacement.
//
// LabelDisp implements LabelArg and DispArg.
type LabelDisp struct {
	l LabelArg
	d DispArg
}

// Get the unique identifier for the label.
func (l Label) Id() uint16 { return l.id }

// Reference the label as an 8-bit relative displacement from the current instruction pointer.
func (l Label) Rel8() Label8 { return Label8(l.id) }

// Reference the label as a 16-bit relative displacement from the current instruction pointer.
func (l Label) Rel16() Label16 { return Label16(l.id) }

// Reference the label as a 32-bit relative displacement from the current instruction pointer.
func (l Label) Rel32() Label32 { return Label32(l.id) }

// Reference the label as an 8-bit relative displacement from the current instruction pointer.
func (l Label) Disp8(d int8) LabelDisp { return LabelDisp{l: l, d: Rel8(d)} }

// Reference the label as a 16-bit relative displacement from the current instruction pointer.
func (l Label) Disp16(d int16) LabelDisp { return LabelDisp{l: l, d: Rel16(d)} }

// Reference the label as a 32-bit relative displacement from the current instruction pointer.
func (l Label) Disp32(d int32) LabelDisp { return LabelDisp{l: l, d: Rel32(d)} }

// Label8 is an 8-bit displacement to a label.
//
// Label8 implements LabelArg and DispArg.
type Label8 uint16

// Label16 is a 16-bit displacement to a label.
//
// Label16 implements LabelArg and DispArg.
type Label16 uint16

// Label32 is a 32-bit displacement to a label.
//
// Label32 implements LabelArg and DispArg.
type Label32 uint16

func (l Label8) isArg()    {}
func (l Label16) isArg()   {}
func (l Label32) isArg()   {}
func (l Label) isArg()     {}
func (l LabelDisp) isArg() {}

func (l Label8) isLabel()    {}
func (l Label16) isLabel()   {}
func (l Label32) isLabel()   {}
func (l Label) isLabel()     {}
func (l LabelDisp) isLabel() {}

func (l Label8) isDisp()    {}
func (l Label16) isDisp()   {}
func (l Label32) isDisp()   {}
func (l Label) isDisp()     {}
func (l LabelDisp) isDisp() {}

func (l Label8) width() uint8    { return 1 }
func (l Label16) width() uint8   { return 2 }
func (l Label32) width() uint8   { return 4 }
func (l Label) width() uint8     { return 4 }
func (l LabelDisp) width() uint8 { return l.d.width() }

func (l Label8) label() uint16    { return uint16(l) }
func (l Label16) label() uint16   { return uint16(l) }
func (l Label32) label() uint16   { return uint16(l) }
func (l Label) label() uint16     { return uint16(l.id) }
func (l LabelDisp) label() uint16 { return l.l.label() }

// Get the additional displacement for the label reference, which is always 0. Use LabelDisp for additional displacement.
func (l Label8) Int32() int32 { return 0 }

// Get the additional displacement for the label reference, which is always 0. Use LabelDisp for additional displacement.
func (l Label16) Int32() int32 { return 0 }

// Get the additional displacement for the label reference, which is always 0. Use LabelDisp for additional displacement.
func (l Label32) Int32() int32 { return 0 }

// Get the additional displacement for the label reference, which is always 0. Use LabelDisp for additional displacement.
func (l Label) Int32() int32 { return 0 }

// Get the additional displacement for the label reference.
func (l LabelDisp) Int32() int32 { return l.d.Int32() }

// RegArg represents any register.
type RegArg interface {
	Arg
	isReg()
}

func isReg(arg Arg) bool {
	_, ok := arg.(RegArg)
	return ok
}

// Reg is a register argument with a specific width and family. All registers have a number
// which distinguishes them within their family, with the exception of the IP/EIP/RIP registers.
//
// Reg implements RegArg.
type Reg uint32

var _ RegArg = Reg(0)

func (r Reg) isArg() {}
func (r Reg) isReg() {}

// Get the family for the register.
//
// If the register is valid, the return value will be REG_LEGACY, REG_RIP, REG_HIGHBYTE, REG_FP,
// REG_MMX, REG_XMM, REG_YMM, REG_SEGMENT, REG_CONTROL, or REG_DEBUG.
func (r Reg) Family() uint8 { return uint8(r >> 8) }

// Get the number which distinguishes the register within its family. The IP/EIP/RIP registers
// have no meaningful number, so they will return 0.
func (r Reg) Num() uint8 { return uint8(r) & 0xf }

// Get the width of the register in bytes.
func (r Reg) Width() uint8 { return r.width() }
func (r Reg) width() uint8 { return uint8(r>>16) & 0x1f }

// Check if the register is numbered 8 or higher. The IP/EIP/RIP registers have no meaningful number,
// so they will return false.
func (r Reg) IsExtended() bool { return r.Num() > 7 }

// Register families
const (
	REG_LEGACY   = iota
	REG_RIP      // IP, EIP, RIP
	REG_HIGHBYTE // AH, CH, DH, BH
	REG_FP
	REG_MMX
	REG_XMM
	REG_YMM
	REG_SEGMENT
	REG_CONTROL
	REG_DEBUG
)

// Registers
const (
	// 8-bit
	AH   Reg = Reg(1<<16 | REG_HIGHBYTE<<8 | 0)
	CH   Reg = Reg(1<<16 | REG_HIGHBYTE<<8 | 1)
	DH   Reg = Reg(1<<16 | REG_HIGHBYTE<<8 | 2)
	BH   Reg = Reg(1<<16 | REG_HIGHBYTE<<8 | 3)
	AL   Reg = Reg(1<<16 | REG_LEGACY<<8 | 0)
	CL   Reg = Reg(1<<16 | REG_LEGACY<<8 | 1)
	DL   Reg = Reg(1<<16 | REG_LEGACY<<8 | 2)
	BL   Reg = Reg(1<<16 | REG_LEGACY<<8 | 3)
	SPB  Reg = Reg(1<<16 | REG_LEGACY<<8 | 4)
	BPB  Reg = Reg(1<<16 | REG_LEGACY<<8 | 5)
	SIB  Reg = Reg(1<<16 | REG_LEGACY<<8 | 6)
	DIB  Reg = Reg(1<<16 | REG_LEGACY<<8 | 7)
	R8B  Reg = Reg(1<<16 | REG_LEGACY<<8 | 8)
	R9B  Reg = Reg(1<<16 | REG_LEGACY<<8 | 9)
	R10B Reg = Reg(1<<16 | REG_LEGACY<<8 | 10)
	R11B Reg = Reg(1<<16 | REG_LEGACY<<8 | 11)
	R12B Reg = Reg(1<<16 | REG_LEGACY<<8 | 12)
	R13B Reg = Reg(1<<16 | REG_LEGACY<<8 | 13)
	R14B Reg = Reg(1<<16 | REG_LEGACY<<8 | 14)
	R15B Reg = Reg(1<<16 | REG_LEGACY<<8 | 15)

	// 16-bit
	AX   Reg = Reg(2<<16 | REG_LEGACY<<8 | 0)
	CX   Reg = Reg(2<<16 | REG_LEGACY<<8 | 1)
	DX   Reg = Reg(2<<16 | REG_LEGACY<<8 | 2)
	BX   Reg = Reg(2<<16 | REG_LEGACY<<8 | 3)
	SP   Reg = Reg(2<<16 | REG_LEGACY<<8 | 4)
	BP   Reg = Reg(2<<16 | REG_LEGACY<<8 | 5)
	SI   Reg = Reg(2<<16 | REG_LEGACY<<8 | 6)
	DI   Reg = Reg(2<<16 | REG_LEGACY<<8 | 7)
	R8W  Reg = Reg(2<<16 | REG_LEGACY<<8 | 8)
	R9W  Reg = Reg(2<<16 | REG_LEGACY<<8 | 9)
	R10W Reg = Reg(2<<16 | REG_LEGACY<<8 | 10)
	R11W Reg = Reg(2<<16 | REG_LEGACY<<8 | 11)
	R12W Reg = Reg(2<<16 | REG_LEGACY<<8 | 12)
	R13W Reg = Reg(2<<16 | REG_LEGACY<<8 | 13)
	R14W Reg = Reg(2<<16 | REG_LEGACY<<8 | 14)
	R15W Reg = Reg(2<<16 | REG_LEGACY<<8 | 15)

	// 32-bit
	EAX  Reg = Reg(4<<16 | REG_LEGACY<<8 | 0)
	ECX  Reg = Reg(4<<16 | REG_LEGACY<<8 | 1)
	EDX  Reg = Reg(4<<16 | REG_LEGACY<<8 | 2)
	EBX  Reg = Reg(4<<16 | REG_LEGACY<<8 | 3)
	ESP  Reg = Reg(4<<16 | REG_LEGACY<<8 | 4)
	EBP  Reg = Reg(4<<16 | REG_LEGACY<<8 | 5)
	ESI  Reg = Reg(4<<16 | REG_LEGACY<<8 | 6)
	EDI  Reg = Reg(4<<16 | REG_LEGACY<<8 | 7)
	R8L  Reg = Reg(4<<16 | REG_LEGACY<<8 | 8)
	R9L  Reg = Reg(4<<16 | REG_LEGACY<<8 | 9)
	R10L Reg = Reg(4<<16 | REG_LEGACY<<8 | 10)
	R11L Reg = Reg(4<<16 | REG_LEGACY<<8 | 11)
	R12L Reg = Reg(4<<16 | REG_LEGACY<<8 | 12)
	R13L Reg = Reg(4<<16 | REG_LEGACY<<8 | 13)
	R14L Reg = Reg(4<<16 | REG_LEGACY<<8 | 14)
	R15L Reg = Reg(4<<16 | REG_LEGACY<<8 | 15)

	// 64-bit
	RAX Reg = Reg(8<<16 | REG_LEGACY<<8 | 0)
	RCX Reg = Reg(8<<16 | REG_LEGACY<<8 | 1)
	RDX Reg = Reg(8<<16 | REG_LEGACY<<8 | 2)
	RBX Reg = Reg(8<<16 | REG_LEGACY<<8 | 3)
	RSP Reg = Reg(8<<16 | REG_LEGACY<<8 | 4)
	RBP Reg = Reg(8<<16 | REG_LEGACY<<8 | 5)
	RSI Reg = Reg(8<<16 | REG_LEGACY<<8 | 6)
	RDI Reg = Reg(8<<16 | REG_LEGACY<<8 | 7)
	R8  Reg = Reg(8<<16 | REG_LEGACY<<8 | 8)
	R9  Reg = Reg(8<<16 | REG_LEGACY<<8 | 9)
	R10 Reg = Reg(8<<16 | REG_LEGACY<<8 | 10)
	R11 Reg = Reg(8<<16 | REG_LEGACY<<8 | 11)
	R12 Reg = Reg(8<<16 | REG_LEGACY<<8 | 12)
	R13 Reg = Reg(8<<16 | REG_LEGACY<<8 | 13)
	R14 Reg = Reg(8<<16 | REG_LEGACY<<8 | 14)
	R15 Reg = Reg(8<<16 | REG_LEGACY<<8 | 15)

	// Instruction pointer.
	IP  Reg = Reg(2<<16 | REG_RIP<<8 | 0) // 16-bit
	EIP Reg = Reg(4<<16 | REG_RIP<<8 | 0) // 32-bit
	RIP Reg = Reg(8<<16 | REG_RIP<<8 | 0) // 64-bit

	// 387 floating point registers.
	F0 Reg = Reg(10<<16 | REG_FP<<8 | 0)
	F1 Reg = Reg(10<<16 | REG_FP<<8 | 1)
	F2 Reg = Reg(10<<16 | REG_FP<<8 | 2)
	F3 Reg = Reg(10<<16 | REG_FP<<8 | 3)
	F4 Reg = Reg(10<<16 | REG_FP<<8 | 4)
	F5 Reg = Reg(10<<16 | REG_FP<<8 | 5)
	F6 Reg = Reg(10<<16 | REG_FP<<8 | 6)
	F7 Reg = Reg(10<<16 | REG_FP<<8 | 7)

	// MMX registers.
	M0 Reg = Reg(8<<16 | REG_MMX<<8 | 0)
	M1 Reg = Reg(8<<16 | REG_MMX<<8 | 1)
	M2 Reg = Reg(8<<16 | REG_MMX<<8 | 2)
	M3 Reg = Reg(8<<16 | REG_MMX<<8 | 3)
	M4 Reg = Reg(8<<16 | REG_MMX<<8 | 4)
	M5 Reg = Reg(8<<16 | REG_MMX<<8 | 5)
	M6 Reg = Reg(8<<16 | REG_MMX<<8 | 6)
	M7 Reg = Reg(8<<16 | REG_MMX<<8 | 7)

	// XMM registers.
	X0  Reg = Reg(16<<16 | REG_XMM<<8 | 0)
	X1  Reg = Reg(16<<16 | REG_XMM<<8 | 1)
	X2  Reg = Reg(16<<16 | REG_XMM<<8 | 2)
	X3  Reg = Reg(16<<16 | REG_XMM<<8 | 3)
	X4  Reg = Reg(16<<16 | REG_XMM<<8 | 4)
	X5  Reg = Reg(16<<16 | REG_XMM<<8 | 5)
	X6  Reg = Reg(16<<16 | REG_XMM<<8 | 6)
	X7  Reg = Reg(16<<16 | REG_XMM<<8 | 7)
	X8  Reg = Reg(16<<16 | REG_XMM<<8 | 8)
	X9  Reg = Reg(16<<16 | REG_XMM<<8 | 9)
	X10 Reg = Reg(16<<16 | REG_XMM<<8 | 10)
	X11 Reg = Reg(16<<16 | REG_XMM<<8 | 11)
	X12 Reg = Reg(16<<16 | REG_XMM<<8 | 12)
	X13 Reg = Reg(16<<16 | REG_XMM<<8 | 13)
	X14 Reg = Reg(16<<16 | REG_XMM<<8 | 14)
	X15 Reg = Reg(16<<16 | REG_XMM<<8 | 15)

	// YMM registers.
	Y0  Reg = Reg(32<<16 | REG_YMM<<8 | 0)
	Y1  Reg = Reg(32<<16 | REG_YMM<<8 | 1)
	Y2  Reg = Reg(32<<16 | REG_YMM<<8 | 2)
	Y3  Reg = Reg(32<<16 | REG_YMM<<8 | 3)
	Y4  Reg = Reg(32<<16 | REG_YMM<<8 | 4)
	Y5  Reg = Reg(32<<16 | REG_YMM<<8 | 5)
	Y6  Reg = Reg(32<<16 | REG_YMM<<8 | 6)
	Y7  Reg = Reg(32<<16 | REG_YMM<<8 | 7)
	Y8  Reg = Reg(32<<16 | REG_YMM<<8 | 8)
	Y9  Reg = Reg(32<<16 | REG_YMM<<8 | 9)
	Y10 Reg = Reg(32<<16 | REG_YMM<<8 | 10)
	Y11 Reg = Reg(32<<16 | REG_YMM<<8 | 11)
	Y12 Reg = Reg(32<<16 | REG_YMM<<8 | 12)
	Y13 Reg = Reg(32<<16 | REG_YMM<<8 | 13)
	Y14 Reg = Reg(32<<16 | REG_YMM<<8 | 14)
	Y15 Reg = Reg(32<<16 | REG_YMM<<8 | 15)

	// Segment registers.
	ES Reg = Reg(2<<16 | REG_SEGMENT<<8 | 0)
	CS Reg = Reg(2<<16 | REG_SEGMENT<<8 | 1)
	SS Reg = Reg(2<<16 | REG_SEGMENT<<8 | 2)
	DS Reg = Reg(2<<16 | REG_SEGMENT<<8 | 3)
	FS Reg = Reg(2<<16 | REG_SEGMENT<<8 | 4)
	GS Reg = Reg(2<<16 | REG_SEGMENT<<8 | 5)

	// Control registers.
	CR0  Reg = Reg(4<<16 | REG_CONTROL<<8 | 0)
	CR1  Reg = Reg(4<<16 | REG_CONTROL<<8 | 1)
	CR2  Reg = Reg(4<<16 | REG_CONTROL<<8 | 2)
	CR3  Reg = Reg(4<<16 | REG_CONTROL<<8 | 3)
	CR4  Reg = Reg(4<<16 | REG_CONTROL<<8 | 4)
	CR5  Reg = Reg(4<<16 | REG_CONTROL<<8 | 5)
	CR6  Reg = Reg(4<<16 | REG_CONTROL<<8 | 6)
	CR7  Reg = Reg(4<<16 | REG_CONTROL<<8 | 7)
	CR8  Reg = Reg(4<<16 | REG_CONTROL<<8 | 8)
	CR9  Reg = Reg(4<<16 | REG_CONTROL<<8 | 9)
	CR10 Reg = Reg(4<<16 | REG_CONTROL<<8 | 10)
	CR11 Reg = Reg(4<<16 | REG_CONTROL<<8 | 11)
	CR12 Reg = Reg(4<<16 | REG_CONTROL<<8 | 12)
	CR13 Reg = Reg(4<<16 | REG_CONTROL<<8 | 13)
	CR14 Reg = Reg(4<<16 | REG_CONTROL<<8 | 14)
	CR15 Reg = Reg(4<<16 | REG_CONTROL<<8 | 15)

	// Debug registers.
	DR0  Reg = Reg(4<<16 | REG_DEBUG<<8 | 0)
	DR1  Reg = Reg(4<<16 | REG_DEBUG<<8 | 1)
	DR2  Reg = Reg(4<<16 | REG_DEBUG<<8 | 2)
	DR3  Reg = Reg(4<<16 | REG_DEBUG<<8 | 3)
	DR4  Reg = Reg(4<<16 | REG_DEBUG<<8 | 4)
	DR5  Reg = Reg(4<<16 | REG_DEBUG<<8 | 5)
	DR6  Reg = Reg(4<<16 | REG_DEBUG<<8 | 6)
	DR7  Reg = Reg(4<<16 | REG_DEBUG<<8 | 7)
	DR8  Reg = Reg(4<<16 | REG_DEBUG<<8 | 8)
	DR9  Reg = Reg(4<<16 | REG_DEBUG<<8 | 9)
	DR10 Reg = Reg(4<<16 | REG_DEBUG<<8 | 10)
	DR11 Reg = Reg(4<<16 | REG_DEBUG<<8 | 11)
	DR12 Reg = Reg(4<<16 | REG_DEBUG<<8 | 12)
	DR13 Reg = Reg(4<<16 | REG_DEBUG<<8 | 13)
	DR14 Reg = Reg(4<<16 | REG_DEBUG<<8 | 14)
	DR15 Reg = Reg(4<<16 | REG_DEBUG<<8 | 15)
)
