package x64

import (
	"fmt"
	"math/bits"

	. "github.com/wdamron/x64/internal/flags"
)

func (a *Assembler) emitInst() error {
	buf := &a.b
	// sanitize memory references, determine address size, and size immediates/displacements if possible
	addrSize, err := a.sanitizeMemArg()
	if err != nil {
		return err
	}
	if addrSize < 0 {
		addrSize = 8
	}

	inst := a.inst.inst

	// find a matching encoding
	if ok := a.matchInst(); !ok {
		return ErrNoMatch
	}

	enc := a.inst.enc

	opSize, err := a.resizeArgs()
	if err != nil {
		return err
	}

	if err := a.extractArgs(); err != nil {
		return err
	}

	ext := a.inst.ext // extracted args
	flags := enc.flags
	op := enc.op[:enc.oplen()]

	// determine if we need an address size override prefix
	prefAddr := addrSize == 4
	if addrSize != 4 && addrSize != 8 {
		return fmt.Errorf("Impossible address size for %s: %v", inst.Name(), addrSize)
	}
	var prefMod byte
	var hasPrefMod bool
	var prefSeg byte
	var hasPrefSeg bool

	var prefSize bool
	var rexW bool
	var vexL bool

	// determine if size prefixes are necessary
	if hasFlag(flags, AUTO_SIZE) || hasFlag(flags, AUTO_NO32) || hasFlag(flags, AUTO_REXW) || hasFlag(flags, AUTO_VEXL) {
		if opSize < 0 {
			return fmt.Errorf("Bad formatting data for %s (op size = %v); no wildcard sizes", inst.Name(), opSize)
		}

		if hasFlag(flags, AUTO_NO32) {
			switch opSize {
			case 2:
				prefSize = true
			case 8:
				// ok
			default:
				return fmt.Errorf("Unsupported operation size for 64-bit mode instruction %s: %v", inst.Name(), opSize)
			}
		} else if hasFlag(flags, AUTO_REXW) {
			switch {
			case opSize == 8:
				rexW = true
			case opSize != 4:
				return fmt.Errorf("16-bit arguments are not supported for %s", inst.Name())
			}
		} else if hasFlag(flags, AUTO_VEXL) {
			switch {
			case opSize == 32:
				vexL = true
			case opSize != 16:
				return fmt.Errorf("Bad operation size for AUTO_VEXL instruction %s: %v", inst.Name(), opSize)
			}
		} else if opSize == 2 {
			prefSize = true
		} else if opSize == 8 {
			rexW = true
		} else if opSize != 4 {
			return fmt.Errorf("Bad operation size for instruction %s: %v", inst.Name(), opSize)
		}
	}

	prefSize = prefSize || hasFlag(flags, WORD_SIZE) || hasFlag(flags, PREF_66)
	rexW = rexW || hasFlag(flags, WITH_REXW)
	vexL = vexL || hasFlag(flags, WITH_VEXL)
	prefAddr = prefAddr || hasFlag(flags, PREF_67)

	switch {
	case hasFlag(flags, PREF_F0):
		prefMod = 0xf0
		hasPrefMod = true
	case hasFlag(flags, PREF_F2):
		prefMod = 0xf2
		hasPrefMod = true
	case hasFlag(flags, PREF_F3):
		prefMod = 0xf3
		hasPrefMod = true
	}

	needRex, err := a.checkRex(rexW)
	if err != nil {
		return err
	}

	var immOp byte
	var hasImmOp bool
	if hasFlag(flags, IMM_OP) {
		immOp = op[len(op)-1]
		op = op[:len(op)-1]
		hasImmOp = true
	}

	if hasPrefSeg {
		buf.Byte(prefSeg)
	}
	if prefAddr {
		buf.Byte(0x67)
	}

	if hasFlag(flags, VEX_OP) || hasFlag(flags, XOP_OP) {
		var pref uint8
		switch {
		case prefSize:
			pref = 1
		case prefMod == 0xf3:
			pref = 2
		case prefMod == 0xf2:
			pref = 3
		}
		// map_sel is stored in the first byte of the opcode
		mapSel := uint8(op[0])
		op = op[1:]
		a.emitVexXop(buf, enc, ext, mapSel, pref, rexW, vexL)
	} else {
		if hasPrefMod {
			buf.Byte(prefMod)
		}
		if prefSize {
			buf.Byte(0x66)
		}
		if needRex {
			a.emitRex(buf, ext.r, ext.m, rexW)
		}
	}

	// if rm is embedded in the last opcode byte, push it here
	if hasFlag(flags, SHORT_ARG) {
		last := op[len(op)-1]
		op = op[:len(op)-1]
		buf.Bytes(op)

		rm := ext.m
		ext.m = nil
		if rm == nil {
			return fmt.Errorf("Bad formatting data for %s", inst.Name())
		}
		reg, ok := rm.(Reg)
		if !ok {
			return fmt.Errorf("Bad formatting data for %s", inst.Name())
		}
		buf.Byte(last + byte(reg.Num())&7)
	} else {
		buf.Bytes(op)
	}

	if ext.m != nil {
		// Direct ModRM addressing
		if r2, ok := ext.m.(Reg); ok {
			r1, ok := ext.r.(Reg)
			if !ok {
				r1 = Reg(Reg(addrSize)<<16 | REG_LEGACY<<8 | Reg(enc.reg()))
			}
			emitMSIB(buf, modDirect, r1, r2)
			// Indirect ModRM (+SIB) addressing
		} else if a.inst.memOffset >= 0 {
			m := a.inst.mem
			r, ok := ext.r.(Reg)
			if !ok {
				r = Reg(Reg(addrSize)<<16 | REG_LEGACY<<8 | Reg(enc.reg()))
			}

			// check addressing mode special cases
			modeVsib := m.Index != 0 && (m.Index.Family() == REG_XMM || m.Index.Family() == REG_YMM)
			mode16 := addrSize == 2
			modeRipRel := m.Base != 0 && m.Base.Family() == REG_RIP
			modeRbpBase := m.Base != 0 && m.Base.Family() == REG_LEGACY && (m.Base.Num() == RBP.Num() || m.Base.Num() == R13.Num())

			if modeVsib {
				base := m.Base
				mode := modDisp8
				if base != 0 {
					if m.Disp != nil && m.Disp.width() != 1 {
						mode = modDisp32
					}
				} else {
					base, mode = RBP, modNoBase
				}

				// always need a SIB byte for VSIB addressing
				emitMSIB(buf, mode, r, Reg(4))
				emitMSIB(buf, uint8(bits.TrailingZeros8(m.Scale)), m.Index, base)

				if m.Disp != nil {
					if mode == modDisp8 {
						buf.Int8(int8(m.Disp.Int32()))
					} else {
						buf.Int32(m.Disp.Int32())
					}
				} else if mode == modDisp8 {
					// no displacement was asked for, but we have to encode one as there's a base
					buf.Int8(0)
				} else {
					// modNoBase requires a dword displacement, and if we got here no displacement was asked for.
					buf.Int32(0)
				}
			} else if mode16 {
				// 16-bit mode: the index/base combination has been encoded in the base register.
				// this register is guaranteed to be present.
				mode := modNoDisp
				switch {
				case m.Disp != nil && m.Disp.width() == 1:
					mode = modDisp8
				case m.Disp != nil:
					mode = modDisp32
				case modeRbpBase:
					mode = modDisp8
				}

				// only need a mod.r/m byte for 16-bit addressing
				emitMSIB(buf, mode, r, m.Base)

				if m.Disp != nil {
					if mode == modDisp8 {
						buf.Int8(int8(m.Disp.Int32()))
					} else {
						buf.Int16(int16(m.Disp.Int32()))
					}
				} else if mode == modDisp8 {
					buf.Int8(0)
				}
			} else if modeRipRel {
				emitMSIB(buf, modNoDisp, r, Reg(5))
				if m.Disp != nil {
					buf.Int32(int32(m.Disp.Int32()))
					if ld, ok := m.Disp.(LabelDisp); ok {
						// the displacement will be patched with the relative label-offset + displacement during ProcessRelocs
						a.relocDisp(ld)
					} else if label, ok := m.Disp.(LabelArg); ok {
						// the displacement will be patched with the relative label-offset during ProcessRelocs
						a.reloc(label.label(), 4)
					}
				} else {
					buf.Int32(0)
				}
			} else {
				// normal addressing
				base := m.Base
				mode := modDisp32
				switch {
				case modeRbpBase && m.Disp == nil:
					// RBP can only be encoded as base if a displacement is present.
					mode = modDisp8
				case m.Disp == nil || base == 0:
					// mode_nodisp if no base is to be encoded. note that in these scenarions a 32-bit disp has to be emitted
					mode = modNoDisp
				case m.Disp != nil && m.Disp.width() == 1:
					mode = modDisp8
				}

				// if there's an index we need to escape into the SIB byte
				if m.Index != 0 {
					if base == 0 {
						base = RBP & (Reg(addrSize) << 16)
					}
					emitMSIB(buf, mode, r, RSP)
					emitMSIB(buf, uint8(bits.TrailingZeros8(m.Scale)), m.Index, base)
				} else if base != 0 {
					emitMSIB(buf, mode, r, base)
				} else {
					emitMSIB(buf, mode, r, RSP)
					emitMSIB(buf, 0, RSP, RBP)
				}

				// displacement
				if m.Disp != nil {
					width := uint8(1)
					if mode == modDisp8 {
						buf.Int8(int8(m.Disp.Int32()))
					} else {
						buf.Int32(m.Disp.Int32())
						width = 4
					}
					if ld, ok := m.Disp.(LabelDisp); ok {
						// the displacement will be patched with the relative label-offset + displacement during ProcessRelocs
						a.relocDisp(ld)
					} else if label, ok := m.Disp.(LabelArg); ok {
						// the displacement will be patched with the relative label-offset during ProcessRelocs
						a.reloc(label.label(), width)
					}
				} else if base == 0 {
					buf.Int32(0)
				} else if mode == modDisp8 {
					buf.Int8(0)
				}

			}
		}
	}

	// opcode encoded after the displacement
	if hasImmOp {
		buf.Byte(immOp)
	}

	// register in immediate argument
	if ext.i != nil {
		ireg := ext.i.(Reg)
		b := ireg.Num() << 4

		if len(ext.imms) > 0 {
			// if immediates are present, the register argument will be merged into the
			// first immediate byte.
			imm, ok := ext.imms[0].(Imm8)
			if !ok {
				return fmt.Errorf("Bad formatting data for %s", inst.Name())
			}
			a.inst.ext.imms = a.inst.ext.imms[1:]
			b = b | (uint8(imm) & 0xf)
		}
		buf.Byte(byte(b))
	}

	// immediates
	for _, arg := range a.inst.ext.imms {
		if imm, ok := arg.(ImmArg); ok {
			switch imm.width() {
			case 1:
				buf.Int8(int8(imm.Int64()))
			case 2:
				buf.Int16(int16(imm.Int64()))
			case 4:
				buf.Int32(int32(imm.Int64()))
			case 8:
				buf.Int64(imm.Int64())
			}
		} else if rel, ok := arg.(RelArg); ok {
			switch rel.width() {
			case 1:
				buf.Int8(int8(rel.Int32()))
			case 2:
				buf.Int16(int16(rel.Int32()))
			case 4:
				buf.Int32(int32(rel.Int32()))
			}
		} else if ld, ok := arg.(LabelDisp); ok {
			width := ld.width()
			switch width {
			case 1:
				buf.Int8(0)
			case 2:
				buf.Int16(0)
			case 4:
				buf.Int32(0)
			default:
				return fmt.Errorf("Invalid label displacement (up to 32-bit displacements are supported): %v", width)
			}
			// the displacement will be patched with the relative label-offset + displacement during ProcessRelocs
			a.relocDisp(ld)
		} else if label, ok := arg.(LabelArg); ok {
			width := label.width()
			switch width {
			case 1:
				buf.Int8(0)
			case 2:
				buf.Int16(0)
			case 4:
				buf.Int32(0)
			default:
				return fmt.Errorf("Invalid label displacement (up to 32-bit displacements are supported): %v", width)
			}
			// the displacement will be patched with the relative label-offset during ProcessRelocs
			a.reloc(label.label(), width)
		}
	}

	return nil
}
