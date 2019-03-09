package x64

import (
	"encoding/binary"
	"fmt"
	"math"
)

// An assembler encodes instructions into a byte slice. Label references are supported, though ProcessRelocs
// must be called to finalize all existing (unprocessed) relative displacements.
//
// When re-using an assembler after encoding a set of instructions, the Reset method must be called beforehand.
type Assembler struct {
	_labels [32]Label
	_relocs [32]reloc

	b           buffer
	labels      []Label
	relocs      []reloc
	nextLabelId uint16
}

type reloc struct {
	loc   uint32 // displacement offset (pc)
	disp  int32  // additional displacement relative to the label offset (pc)
	label uint16 // target label.id
	_     byte
	_     byte
	_     byte
	width uint8 // displacement width
}

// Create a new Assembler for instruction encoding. Output will be encoded to buf. If the encoded output
// exceeds the length of buf, a new slice will be allocated.
func NewAssembler(buf []byte) *Assembler {
	a := Assembler{b: buffer{b: buf, i: 0, sz: len(buf)}}
	a.labels = a._labels[:0]
	a.relocs = a._relocs[:0]
	return &a
}

// Reset the assembler before encoding a new set of instructions. All existing labels will be cleared,
// the buffer will be cleared, and the PC will be reset to 0.
func (a *Assembler) Reset() {
	a.b.Reset()
	a.nextLabelId = 0
	a.labels = a._labels[:0]
	a.relocs = a._relocs[:0]
}

// Get the current encoded instructions. This method may be called multiple times and does not affect the
// underlying code buffer.
func (a *Assembler) Code() []byte { return a.b.Get() }

// Get the current program counter (i.e. number of bytes written to the encoding buffer).
func (a *Assembler) PC() uint32 { return uint32(a.b.i) }

// Set the current program counter (i.e. number of bytes written to the encoding buffer).
func (a *Assembler) SetPC(pc uint32) { a.b.i = int(pc) }

// Align the program counter to a power-of-2 offset. Intermediate space will be filled with NOPs.
func (a *Assembler) AlignPC(pow2 uint8) { a.b.Nop(pow2 - (uint8(a.PC()) & (pow2 - 1))) }

// Encode inst with args to the encoding buffer.
func (a *Assembler) Inst(inst Inst, args ...Arg) error {
	var argv [4]Arg
	for i, arg := range args {
		argv[i] = arg
	}
	argc := len(args)
	return a.emitInst(inst, argc, &argv)
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
// the ProcessRelocs method.
func (a *Assembler) NewLabel() Label {
	l := Label{pc: a.PC(), id: a.nextLabelId}
	a.labels = append(a.labels, l)
	a.nextLabelId++
	return l
}

// Update the PC assigned to the label using the current PC.
func (a *Assembler) SetLabel(label Label) { a.labels[label.id].pc = a.PC() }

// Update the PC assigned to the label using the given PC.
func (a *Assembler) SetLabelPC(label Label, pc uint32) { a.labels[label.id].pc = pc }

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
		disp:  ld.d.Int32(),
		label: ld.l.label(),
		width: width,
	})
}

// Process all label references. Each label reference will have its displacement patched with the relative
// offset to the label (optionally with additional displacement for LabelDisp arguments).
func (a *Assembler) ProcessRelocs() error {
	ls := a.labels
	rs := a.relocs
	for _, r := range rs {
		l := ls[r.label]
		delta := int(r.loc) + int(r.width) - int(l.pc)
		disp := -delta + int(r.disp)
		switch r.width {
		case 1:
			if disp > math.MaxInt8 || disp < math.MinInt8 {
				return fmt.Errorf("Relative label offset exceeds range for 8-bit immediate")
			}
			a.b.b[r.loc] = byte(disp)
		case 2:
			if disp > math.MaxInt16 || disp < math.MinInt16 {
				return fmt.Errorf("Relative label offset exceeds range for 16-bit immediate")
			}
			binary.LittleEndian.PutUint16(a.b.b[r.loc:], uint16(disp))
		case 4:
			if disp > math.MaxInt32 || disp < math.MinInt32 {
				return fmt.Errorf("Relative label offset exceeds range for 32-bit immediate")
			}
			binary.LittleEndian.PutUint32(a.b.b[r.loc:], uint32(disp))
		}
	}
	return nil
}
