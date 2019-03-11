package x64

import (
	. "github.com/wdamron/x64/feats"
)

// Get the format bytes for the given arg-pattern identifier:
func argp(pid uint8) [8]byte { return argpFormats[pid] }

func hasFlag(flags, flag uint32) bool { return flags&flag != 0 }

// Inst represents an instruction-mnemonic.
//
// 	[0..12] bits are a uint16 offset into an internal array of instruction-encodings
// 	[16..20] bits specify the number of supported encodings for the instruction
// 	[21..31] bits identify the unique mnemonic
type Inst uint32

// Get the unique numeric identifier for the instruction mnemonic. This is an arbitrary value.
func (inst Inst) Id() uint16     { return uint16(inst >> 21) }
func (inst Inst) offset() uint16 { return uint16(inst) & 0xfff }
func (inst Inst) count() uint8   { return uint8(inst>>16) & 0x1f }

// Get the name of the instruction mnemonic.
func (inst Inst) Name() string {
	idOffset := inst.Id() - 1
	nmOffset := instNameOffsets[idOffset]
	var nmLength uint16
	if idOffset < uint16(len(instNameOffsets))-1 {
		nmLength = instNameOffsets[idOffset+1] - nmOffset
	} else {
		nmLength = uint16(len(instNames)) - nmOffset
	}
	return instNames[nmOffset : nmOffset+nmLength]
}

func (inst Inst) encs() []enc {
	off := inst.offset()
	return encs[off : off+uint16(inst.count())]
}

// enc represents an instruction-encoding spec.
//
// * Format:
//   * opcode: [4]byte
//   * flags: uint32
//   * feats: uint32
//   * mnemonic: uint16
//     * [0..10] bits identify the unique mnemonic (reverse mapping to the mnemonic)
//     * [11..15] bits identify the offset of this encoding w.r.t. the starting offset for the mnemonic within the encodings array
//   * reg + opcode-length: byte
//     * [0..3] bits identify the reg
//     * [4..6] bits specify the opcode length (0 -> 1-byte, 1 -> 2-byte, 2 -> 3-byte, 3 -> 4-byte)
//   * arg-pattern: byte (254 possible combinations)
type enc struct {
	op       [4]byte
	flags    uint32
	feats    Feature
	mne      uint16
	regoplen uint8
	argp     uint8
}

func (e enc) reg() int8 {
	r := e.regoplen & 0xf
	if r == 0xf {
		return -1
	}
	return int8(r)
}

func (e enc) oplen() uint8    { return (e.regoplen >> 4) }
func (e enc) instid() uint16  { return e.mne & 0x7ff }
func (e enc) offset() uint8   { return uint8(e.mne >> 11) }
func (e enc) format() [8]byte { return argpFormats[e.argp] }
