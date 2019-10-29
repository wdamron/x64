package x64

import (
	"fmt"

	"github.com/wdamron/x64/feats"
	flags "github.com/wdamron/x64/internal/flags"
)

// Placeholder for memory arguments, to avoid allocations when converting Mem to an interface
type memArgPlaceholder struct{}

func (m memArgPlaceholder) isArg()       {}
func (m memArgPlaceholder) width() uint8 { return 0 }

// InstMatcher finds valid encodings for an instruction with arguments.
type InstMatcher struct {
	// enabled CPU features:
	feats feats.Feature

	// scratch space for current instruction, arguments, and matched encoding:

	addrSize int
	opSize   int

	memOffset int   // -1 if no memory argument is present
	mem       Mem   // memory argument if memOffset >= 0
	args      []Arg // sized reference to _args
	_args     [4]Arg

	inst  Inst
	encId uint   // offset of the matched encoding
	enc   enc    // matched encoding
	argp  []byte // arg-pattern for the matched encoding

	// extracted arguments:

	r Arg
	m Arg
	v Arg
	i Arg

	imms  []Arg
	_imms [4]Arg
}

// Create an instruction matcher with all CPU features enabled by default.
func NewInstMatcher() *InstMatcher {
	return &InstMatcher{
		feats:     feats.AllFeatures,
		memOffset: -1,
		addrSize:  -1,
		opSize:    -1,
	}
}

func (m *InstMatcher) reset() {
	*m = InstMatcher{feats: m.feats, addrSize: -1, opSize: -1, memOffset: -1}
}

// Get the current, allowable CPU feature-set for instruction-matching.
//
// See package x64/feats for all available CPU features.
func (m *InstMatcher) Features() feats.Feature { return m.feats }

// Restrict the allowable CPU feature-set for instruction-matching.
//
// See package x64/feats for all available CPU features.
func (m *InstMatcher) SetFeatures(enabledFeatures feats.Feature) { m.feats = enabledFeatures }

// Control the allowable CPU feature-set for instruction-matching.
//
// See package x64/feats for all available CPU features.
func (m *InstMatcher) DisableFeature(feature feats.Feature) { m.feats &^= feature }

// Control the allowable CPU feature-set for instruction-matching.
//
// See package x64/feats for all available CPU features.
func (m *InstMatcher) EnableFeature(feature feats.Feature) { m.feats |= feature }

// Get the instruction's unique encoding ID.
func (m *InstMatcher) EncodingId() uint { return m.encId }

// Get CPU features required by the instruction.
func (m *InstMatcher) InstFeatures() feats.Feature { return m.enc.feats }

// Get the instruction's address size.
func (m *InstMatcher) AddrSize() int { return m.addrSize }

// Get the instruction's operand size.
func (m *InstMatcher) OperandSize() int { return m.opSize }

// Get the instruction's opcode
func (m *InstMatcher) Opcode() []byte { return m.enc.op[:m.enc.oplen()] }

// Check if a register argument will be encoded in the last byte of the instruction's opcode.
func (m *InstMatcher) HasOpcodeRegArg() bool { return m.enc.flags&flags.SHORT_ARG != 0 }

// Check if the instruction is part of the VEX instruction set.
func (m *InstMatcher) IsVEX() bool { return m.enc.flags&flags.VEX_OP != 0 }

// Check if the instruction is part of the XOP instruction set.
func (m *InstMatcher) IsXOP() bool { return m.enc.flags&flags.XOP_OP != 0 }

// Check if the instruction encodes the final opcode byte in the immediate position, like 3DNow! ops.
func (m *InstMatcher) HasOpcodeInImmediate() bool { return m.enc.flags&flags.IMM_OP != 0 }

func (m *InstMatcher) Match(inst Inst, args ...Arg) error {
	if err := m.prepare(inst, args...); err != nil {
		return err
	}
	return m.match(0)
}

// Find all matching encodings for an instruction. If no matches are found, ErrNoMatch will be returned.
func (m *InstMatcher) AllMatches(inst Inst, args ...Arg) ([]InstMatcher, error) {
	var matches []InstMatcher
	start := uint16(inst.offset())
	count := uint16(inst.count())
	offset := uint16(0)
	for offset < count {
		if err := m.prepare(inst, args...); err != nil {
			return nil, err
		}
		if err := m.match(offset); err == nil {
			matches = append(matches, *m)
			offset = uint16(m.EncodingId()) + 1 - start
			continue
		}
		offset++
	}
	m.reset()
	if len(matches) == 0 {
		return nil, ErrNoMatch
	}
	return matches, nil
}

func (m *InstMatcher) prepare(inst Inst, args ...Arg) error {
	m.reset()
	m.inst = inst
	for i, arg := range args {
		if mem, ok := arg.(Mem); ok {
			if m.memOffset >= 0 {
				m.reset()
				return fmt.Errorf("Multiple memory arguments are not supported")
			}
			m._args[i] = memArgPlaceholder{}
			m.memOffset = i
			m.mem = mem
			continue
		}
		m._args[i] = arg
	}
	m.args = m._args[:len(args)]
	return nil
}

func (m *InstMatcher) match(encodingStartOffset uint16) error {
	addrSize, err := m.sanitizeMemArg()
	if err != nil {
		m.reset()
		return err
	}
	if addrSize < 0 {
		addrSize = 8
	}

	if addrSize != 4 && addrSize != 8 {
		return fmt.Errorf("Impossible address size for %s: %v", m.inst.Name(), addrSize)
	}

	// find a matching encoding
	if ok := m.matchInst(m.feats, encodingStartOffset); !ok {
		m.reset()
		return ErrNoMatch
	}

	opSize, err := m.resizeArgs()
	if err != nil {
		m.reset()
		return err
	}

	if err = m.extractArgs(); err != nil {
		m.reset()
		return err
	}

	m.addrSize, m.opSize = int(addrSize), int(opSize)

	return nil
}

// Find an encoding for inst with a register destination and register source.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (m *InstMatcher) RR(inst Inst, dst, src Reg) error {
	return m.regRegImm(inst, dst, src, nil)
}

// Find an encoding for inst with a register destination, register source, and immediate.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (m *InstMatcher) RRI(inst Inst, dst, src Reg, imm ImmArg) error {
	return m.regRegImm(inst, dst, src, imm)
}

// Find an encoding for inst with a register destination and memory source.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (m *InstMatcher) RM(inst Inst, dst Reg, src Mem) error {
	return m.regMemImm(inst, dst, src, nil, false)
}

// Find an encoding for inst with a memory destination and register source.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (m *InstMatcher) MR(inst Inst, dst Mem, src Reg) error {
	return m.regMemImm(inst, src, dst, nil, true)
}

// Find an encoding for inst with a register destination, memory source, and immediate.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (m *InstMatcher) RMI(inst Inst, dst Reg, src Mem, imm ImmArg) error {
	return m.regMemImm(inst, dst, src, imm, false)
}

// Find an encoding for inst with a memory destination, register source, and immediate.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (m *InstMatcher) MRI(inst Inst, dst Mem, src Reg, imm ImmArg) error {
	return m.regMemImm(inst, src, dst, imm, true)
}

// Find an encoding for inst with a register destination and immediate.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (m *InstMatcher) RI(inst Inst, dst Reg, imm ImmArg) error {
	m.reset()
	m.inst = inst
	m._args[0], m._args[1] = dst, imm
	if imm != nil {
		m.args = m._args[:2]
	} else {
		m.args = m._args[:1]
	}
	return m.match(0)
}

// Find an encoding for inst with a memory destination and immediate.
// If no matching instruction-encoding is found, ErrNoMatch will be returned.
func (m *InstMatcher) MI(inst Inst, dst Mem, imm ImmArg) error {
	m.reset()
	m.inst, m.memOffset, m.mem, m._args[0], m._args[1] = inst, 0, dst, memArgPlaceholder{}, imm
	if imm != nil {
		m.args = m._args[:2]
	} else {
		m.args = m._args[:1]
	}
	return m.match(0)
}

func (m *InstMatcher) regRegImm(inst Inst, dst, src Reg, imm ImmArg) error {
	m.reset()
	m.inst, m._args[0], m._args[1], m._args[2] = inst, dst, src, imm
	if imm != nil {
		m.args = m._args[:3]
	} else {
		m.args = m._args[:2]
	}
	return m.match(0)
}

func (m *InstMatcher) regMemImm(inst Inst, r Reg, mem Mem, imm ImmArg, swap bool) error {
	m.reset()
	m.inst, m.mem = inst, mem
	if swap {
		m.memOffset = 0
		m._args[0], m._args[1] = memArgPlaceholder{}, r
	} else {
		m.memOffset = 1
		m._args[0], m._args[1] = r, memArgPlaceholder{}
	}
	if imm != nil {
		m._args[2] = imm
		m.args = m._args[:3]
	} else {
		m.args = m._args[:2]
	}
	return m.match(0)
}
