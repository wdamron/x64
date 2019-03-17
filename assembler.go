package x64

import (
	"encoding/binary"
	"fmt"
	"math"

	. "github.com/wdamron/x64/feats"
)

// An assembler encodes instructions into a byte slice. Label references are supported, though Finalize
// must be called to finalize all existing (unprocessed) relative displacements.
//
// When re-using an assembler after encoding a set of instructions, the Reset method must be called beforehand.
type Assembler struct {
	b           buffer
	labels      []Label
	relocs      []reloc
	feats       Feature
	nextLabelId uint16
	err         error

	inst instArgsEnc // current instruction (value is non-zero only while encoding)

	_labels [32]Label
	_relocs [32]reloc
}

// Create a new Assembler for instruction encoding. Output will be encoded to buf. If the encoded output
// exceeds the length of buf, a new slice will be allocated.
//
// All CPU features will be enabled by default, for instruction-matching.
func NewAssembler(buf []byte) *Assembler {
	a := Assembler{b: buffer{b: buf, i: 0, sz: len(buf)}, feats: AllFeatures}
	a.labels = a._labels[:0]
	a.relocs = a._relocs[:0]
	return &a
}

func (a *Assembler) Nop(length uint8) {
	a.b.Nop(length)
}

type instArgsEnc struct {
	args      []Arg // sized reference to _args
	inst      Inst
	memOffset int // -1 if no memory argument is present
	mem       Mem // memory argument if memOffset >= 0

	enc  enc    // matched encoding
	argp []byte // arg-pattern for the matched encoding

	ext extractedArgs

	_args [4]Arg
}

type extractedArgs struct {
	r Arg
	m Arg
	v Arg
	i Arg

	imms  []Arg
	_imms [4]Arg
}

// Placeholder for memory arguments, to avoid allocations when converting Mem to an interface
type memArgPlaceholder struct{}

func (m memArgPlaceholder) isArg()       {}
func (m memArgPlaceholder) width() uint8 { return 0 }

type reloc struct {
	loc   uint32 // displacement offset (pc)
	disp  int32  // additional displacement relative to the label offset (pc)
	label uint16 // target label.id
	_     byte
	_     byte
	_     byte
	width uint8 // displacement width
}

// Get the current, allowable CPU feature-set for instruction-matching.
//
// See package x64/feats for all available CPU features.
func (a *Assembler) Features() Feature { return a.feats }

// Restrict the allowable CPU feature-set for instruction-matching. This will not affect
// instructions which have already been encoded.
//
// See package x64/feats for all available CPU features.
func (a *Assembler) SetFeatures(enabledFeatures Feature) { a.feats = enabledFeatures }

// Control the allowable CPU feature-set for instruction-matching. This will not affect
// instructions which have already been encoded.
//
// See package x64/feats for all available CPU features.
func (a *Assembler) DisableFeature(feature Feature) { a.feats &^= feature }

// Control the allowable CPU feature-set for instruction-matching. This will not affect
// instructions which have already been encoded.
//
// See package x64/feats for all available CPU features.
func (a *Assembler) EnableFeature(feature Feature) { a.feats |= feature }

// Reset an assembler before encoding a new set of instructions. All existing labels will be cleared,
// the error will be cleared if one exists, and the PC will be reset to 0. The current set of enabled
// CPU features will be retained.
//
// If buf is not nil, the assembler's buffer will be replaced with buf; otherwise, the assembler's
// buffer will be reset and possibly resized.
func (a *Assembler) Reset(buf []byte) {
	if buf != nil {
		a.b = buffer{b: buf, i: 0, sz: len(buf)}
	} else {
		a.b.Reset()
	}
	a.nextLabelId = 0
	a.err = nil
	a.inst = instArgsEnc{}
	a.labels = a._labels[:0]
	a.relocs = a._relocs[:0]
}

// Get the first error which occured while encoding or finalizing instructions, since the assembler
// was last reset (or initialized, if the assembler has not been reset).
func (a *Assembler) Err() error { return a.err }

// Get the current encoded instructions. This method may be called multiple times and does not affect the
// underlying code buffer.
func (a *Assembler) Code() []byte { return a.b.Get() }

// Get the current program counter (i.e. number of bytes written to the encoding buffer).
func (a *Assembler) PC() uint32 { return uint32(a.b.i) }

// Set the current program counter (i.e. number of bytes written to the encoding buffer).
func (a *Assembler) SetPC(pc uint32) {
	if int(pc) >= a.b.Cap() {
		a.b.extend(int(pc) + 1 - a.b.Cap())
	}
	a.b.i = int(pc)
}

// Align the program counter to a power-of-2 offset. Intermediate space will be filled with NOPs.
func (a *Assembler) AlignPC(pow2 uint8) { a.b.Nop(pow2 - (uint8(a.PC()) & (pow2 - 1))) }

// Encode inst with args to the encoding buffer. If no matching instruction-encoding is found,
// ErrNoMatch will be returned.
func (a *Assembler) Inst(inst Inst, args ...Arg) error {
	if a.err != nil {
		return a.err
	}
	a.inst = instArgsEnc{inst: inst, memOffset: -1}
	for i, arg := range args {
		if mem, ok := arg.(Mem); ok {
			if a.inst.memOffset >= 0 {
				a.err = fmt.Errorf("Multiple memory arguments are not supported")
				a.inst = instArgsEnc{}
				return a.err
			}
			a.inst._args[i] = memArgPlaceholder{}
			a.inst.memOffset = i
			a.inst.mem = mem
			continue
		}
		a.inst._args[i] = arg
	}
	a.inst.args = a.inst._args[:len(args)]
	if err := a.emitInst(); err != nil {
		a.err = err
		a.inst = instArgsEnc{}
		return err
	}
	a.inst = instArgsEnc{}
	return nil
}

// Encode an instruction to load the address of the current goroutine into a register.
// The instruction will move the address from [FS:-8] to r.
func (a *Assembler) G(r Reg) error {
	return a.Inst(MOV, r, Mem{Base: FS, Disp: Rel8(-8)})
}

// Encode an instruction to load the stack-guard address for the current goroutine into a register.
//
// r will contain the stack-guard address for the current goroutine after the instruction executes.
//
// g must be a register containing the address of the current goroutine.
func (a *Assembler) SG(r, g Reg) error {
	return a.Inst(MOV, r, Mem{Base: g, Disp: Rel8(16)})
}

// Encode inst with a register destination and register source to the encoding buffer.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (a *Assembler) RR(inst Inst, dst, src Reg) error {
	return a.regRegImm(inst, dst, src, nil)
}

// Encode inst with a register destination, register source, and immediate to the encoding buffer.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (a *Assembler) RRI(inst Inst, dst, src Reg, imm ImmArg) error {
	return a.regRegImm(inst, dst, src, imm)
}

// Encode inst with a register destination and memory source to the encoding buffer.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (a *Assembler) RM(inst Inst, dst Reg, src Mem) error {
	return a.regMemImm(inst, dst, src, nil, false)
}

// Encode inst with a memory destination and register source to the encoding buffer.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (a *Assembler) MR(inst Inst, dst Mem, src Reg) error {
	return a.regMemImm(inst, src, dst, nil, true)
}

// Encode inst with a register destination, memory source, and immediate to the encoding buffer.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (a *Assembler) RMI(inst Inst, dst Reg, src Mem, imm ImmArg) error {
	return a.regMemImm(inst, dst, src, imm, false)
}

// Encode inst with a memory destination, register source, and immediate to the encoding buffer.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (a *Assembler) MRI(inst Inst, dst Mem, src Reg, imm ImmArg) error {
	return a.regMemImm(inst, src, dst, imm, true)
}

// Encode inst with a register destination and immediate to the encoding buffer.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (a *Assembler) RI(inst Inst, dst Reg, imm ImmArg) error {
	if a.err != nil {
		return a.err
	}
	a.inst = instArgsEnc{inst: inst, memOffset: -1}
	a.inst._args[0], a.inst._args[1] = dst, imm
	if imm != nil {
		a.inst.args = a.inst._args[:2]
	} else {
		a.inst.args = a.inst._args[:1]
	}
	if err := a.emitInst(); err != nil {
		a.err = err
		a.inst = instArgsEnc{}
		return err
	}
	a.inst = instArgsEnc{}
	return nil
}

// Encode inst with a memory destination and immediate to the encoding buffer.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (a *Assembler) MI(inst Inst, dst Mem, imm ImmArg) error {
	if a.err != nil {
		return a.err
	}
	a.inst = instArgsEnc{inst: inst, memOffset: 0, mem: dst}
	a.inst._args[0], a.inst._args[1] = memArgPlaceholder{}, imm
	if imm != nil {
		a.inst.args = a.inst._args[:2]
	} else {
		a.inst.args = a.inst._args[:1]
	}
	if err := a.emitInst(); err != nil {
		a.err = err
		a.inst = instArgsEnc{}
		return err
	}
	a.inst = instArgsEnc{}
	return nil
}

func (a *Assembler) regRegImm(inst Inst, dst, src Reg, imm ImmArg) error {
	if a.err != nil {
		return a.err
	}
	a.inst = instArgsEnc{inst: inst, memOffset: -1}
	a.inst._args[0], a.inst._args[1], a.inst._args[2] = dst, src, imm
	if imm != nil {
		a.inst.args = a.inst._args[:3]
	} else {
		a.inst.args = a.inst._args[:2]
	}
	if err := a.emitInst(); err != nil {
		a.err = err
		a.inst = instArgsEnc{}
		return err
	}
	a.inst = instArgsEnc{}
	return nil
}

func (a *Assembler) regMemImm(inst Inst, r Reg, m Mem, imm ImmArg, swap bool) error {
	if a.err != nil {
		return a.err
	}
	a.inst = instArgsEnc{inst: inst, mem: m}
	if swap {
		a.inst.memOffset = 0
		a.inst._args[0], a.inst._args[1] = memArgPlaceholder{}, r
	} else {
		a.inst.memOffset = 1
		a.inst._args[0], a.inst._args[1] = r, memArgPlaceholder{}
	}
	if imm != nil {
		a.inst._args[2] = imm
		a.inst.args = a.inst._args[:3]
	} else {
		a.inst.args = a.inst._args[:2]
	}
	if err := a.emitInst(); err != nil {
		a.err = err
		a.inst = instArgsEnc{}
		return err
	}
	a.inst = instArgsEnc{}
	return nil
}

// Write raw data to the encoding buffer.
func (a *Assembler) Raw(data []byte) { a.b.Bytes(data) }

// Write a raw byte to the encoding buffer.
func (a *Assembler) RawByte(b byte) { a.b.Byte(b) }

// Write a raw 16-bit integer to the encoding buffer.
func (a *Assembler) Raw16(i int16) { a.b.Int16(i) }

// Write a raw 32-bit integer to the encoding buffer.
func (a *Assembler) Raw32(i int32) { a.b.Int32(i) }

// Write a raw 64-bit integer to the encoding buffer.
func (a *Assembler) Raw64(i int64) { a.b.Int64(i) }

// Create a new label at the current PC. To update the PC assigned to the label, call the SetLabel
// method with the label when the PC reaches the desired offset -- this must be done before calling
// the Finalize method.
func (a *Assembler) NewLabel() Label {
	l := Label{pc: a.PC(), id: a.nextLabelId}
	a.labels = append(a.labels, l)
	a.nextLabelId++
	return l
}

// Update the PC assigned to the label using the current PC.
func (a *Assembler) SetLabel(label Label) { a.labels[label.id].pc = a.PC() }

// Get the PC currently assigned to the label.
func (a *Assembler) GetLabelPC(label LabelArg) uint32 { return a.labels[label.label()].pc }

// Update the PC assigned to the label using the given PC. Finalize must be called to update
// existing label references after labels have been reassigned to new offsets, though Finalize
// only needs to be called after a set of updates (i.e. not after each update).
func (a *Assembler) SetLabelPC(label LabelArg, pc uint32) { a.labels[label.label()].pc = pc }

func (a *Assembler) reloc(labelId uint16, dispSize uint8) {
	a.relocs = append(a.relocs, reloc{
		loc:   a.PC() - uint32(dispSize),
		label: labelId,
		width: dispSize,
	})
}

func (a *Assembler) relocDisp(ld LabelDisp) {
	width := ld.width()
	a.relocs = append(a.relocs, reloc{
		loc:   a.PC() - uint32(width),
		disp:  ld.disp,
		label: ld.labelid,
		width: width,
	})
}

// Process all label references. Each label reference will have its displacement patched with the relative
// offset to the label (optionally with additional displacement for LabelDisp arguments).
func (a *Assembler) Finalize() error {
	if a.err != nil {
		return a.err
	}
	ls := a.labels
	rs := a.relocs
	for _, r := range rs {
		l := ls[r.label]
		delta := int(r.loc) + int(r.width) - int(l.pc)
		disp := -delta + int(r.disp)
		switch r.width {
		case 1:
			if disp > math.MaxInt8 || disp < math.MinInt8 {
				a.err = fmt.Errorf("Relative label offset exceeds range for 8-bit immediate")
				return a.err
			}
			a.b.b[r.loc] = byte(disp)
		case 2:
			if disp > math.MaxInt16 || disp < math.MinInt16 {
				a.err = fmt.Errorf("Relative label offset exceeds range for 16-bit immediate")
				return a.err
			}
			binary.LittleEndian.PutUint16(a.b.b[r.loc:], uint16(disp))
		case 4:
			if disp > math.MaxInt32 || disp < math.MinInt32 {
				a.err = fmt.Errorf("Relative label offset exceeds range for 32-bit immediate")
				return a.err
			}
			binary.LittleEndian.PutUint32(a.b.b[r.loc:], uint32(disp))
		}
	}
	return nil
}
