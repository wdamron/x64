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
	disp    int32
	labelid uint16
	dispsz  uint8
	_       uint8
}

// Get the unique identifier for the label.
func (l Label) Id() uint16 { return l.id }

// Reference the label as an 8-bit relative displacement from the current instruction pointer.
func (l Label) Rel8() Label8 { return Label8(l.id) }

// Reference the label as a 16-bit relative displacement from the current instruction pointer.
func (l Label) Rel16() Label16 { return Label16(l.id) }

// Reference the label as a 32-bit relative displacement from the current instruction pointer.
func (l Label) Rel32() Label32 { return Label32(l.id) }

// Reference the label as an 8-bit relative displacement from the current instruction pointer,
// with additional displacement provided by d.
func (l Label) Disp8(d int8) LabelDisp {
	return LabelDisp{labelid: l.label(), disp: int32(d), dispsz: 1}
}

// Reference the label as a 16-bit relative displacement from the current instruction pointer,
// with additional displacement provided by d.
func (l Label) Disp16(d int16) LabelDisp {
	return LabelDisp{labelid: l.label(), disp: int32(d), dispsz: 2}
}

// Reference the label as a 32-bit relative displacement from the current instruction pointer,
// with additional displacement provided by d.
func (l Label) Disp32(d int32) LabelDisp {
	return LabelDisp{labelid: l.label(), disp: d, dispsz: 4}
}

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
func (l LabelDisp) width() uint8 { return l.dispsz }

func (l Label8) label() uint16    { return uint16(l) }
func (l Label16) label() uint16   { return uint16(l) }
func (l Label32) label() uint16   { return uint16(l) }
func (l Label) label() uint16     { return uint16(l.id) }
func (l LabelDisp) label() uint16 { return l.labelid }

// Get the additional displacement for the label reference, which is always 0. Use LabelDisp for additional displacement.
func (l Label8) Int32() int32 { return 0 }

// Get the additional displacement for the label reference, which is always 0. Use LabelDisp for additional displacement.
func (l Label16) Int32() int32 { return 0 }

// Get the additional displacement for the label reference, which is always 0. Use LabelDisp for additional displacement.
func (l Label32) Int32() int32 { return 0 }

// Get the additional displacement for the label reference, which is always 0. Use LabelDisp for additional displacement.
func (l Label) Int32() int32 { return 0 }

// Get the additional displacement for the label reference.
func (l LabelDisp) Int32() int32 { return l.disp }
