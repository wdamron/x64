package x64

import (
	"fmt"

	. "github.com/wdamron/x64/flags"
)

const (
	modDirect uint8 = 3
	modNoDisp uint8 = 0 // normal addressing
	modNoBase uint8 = 0 // VSIB addressing
	modDisp8  uint8 = 1
	modDisp32 uint8 = 2
)

func (a *Assembler) checkRex(rexW bool) (bool, error) {
	argp := a.inst.argp
	plen := len(argp)
	args := a.inst.args
	argc := len(args)
	requiresRex := rexW
	requiresNoRex := false

	// scan arg-pattern:
	for pi, ai := 0, 0; pi+1 < plen && ai < argc; pi, ai = pi+2, ai+1 {
		t, arg := argp[pi], args[ai]

		if t >= 'a' && t <= 'z' {
			switch v := arg.(type) {
			case Reg:
				if v.Family() == REG_HIGHBYTE {
					requiresNoRex = true
				} else if v.IsExtended() || (v.width() == 1 && (v.Num() == SP.Num() || v.Num() == BP.Num() || v.Num() == SI.Num() || v.Num() == DI.Num())) {
					requiresRex = true
				}
			case memArgPlaceholder:
				mem := a.inst.mem
				if mem.Base != 0 {
					requiresRex = requiresRex || mem.Base.IsExtended()
				}
				if mem.Index != 0 {
					requiresRex = requiresRex || mem.Index.IsExtended()
				}
			}
		}
	}

	if requiresRex && requiresNoRex {
		return requiresRex, fmt.Errorf("Unsupported high-byte register combined with extended registers or 64-bit argument-size")
	}

	return requiresRex, nil
}

func (a *Assembler) emitRex(buf *buffer, r, rm Arg, rexW bool) {
	regN, indexN, baseN := uint8(0), uint8(0), uint8(0)

	if reg, ok := r.(Reg); ok {
		regN = reg.Num()
	}
	switch v := rm.(type) {
	case Reg:
		baseN = v.Num()
	case memArgPlaceholder:
		mem := a.inst.mem
		if mem.Base != 0 {
			baseN = mem.Base.Num()
		}
		if mem.Index != 0 {
			indexN = mem.Index.Num()
		}
	}
	bitW := uint8(0)
	if rexW {
		bitW = 1
	}
	rex := byte(0x40 | (bitW << 3) | (regN&8)>>1 | (indexN&8)>>2 | (baseN&8)>>3)
	buf.Byte(rex)
}

func emitMSIB(buf *buffer, mode uint8, r, rm Reg) {
	buf.Byte(byte(mode<<6) | byte((r.Num()&7)<<3) | byte(rm.Num()&7))
}

func (a *Assembler) emitVexXop(buf *buffer, e enc, ext extractedArgs, mapSel, pref uint8, rexW, vexL bool) {
	var reg, index, base, vvvv Reg

	var b1, b2 uint8
	if ext.r != nil {
		if r, ok := ext.r.(Reg); ok {
			reg = r
		}
		if r, ok := ext.m.(Reg); ok {
			base = r
		} else if _, ok := ext.m.(memArgPlaceholder); ok {
			m := a.inst.mem
			if m.Base != 0 {
				base = m.Base
			}
			if m.Index != 0 {
				index = m.Index
			}
		}
		b1 = (mapSel & 0x1f) | ((^reg.Num())&8)<<4 | ((^index.Num())&8)<<3 | ((^base.Num())&8)<<2
	}

	if ext.v != nil {
		if r, ok := ext.v.(Reg); ok {
			vvvv = r
		}
	}
	rexWb := uint8(0)
	if rexW {
		rexWb = 1
	}
	vexLb := uint8(0)
	if vexL {
		vexLb = 1
	}
	b2 = (pref & 0x3) | rexWb<<7 | ((^vvvv.Num())&0xf)<<3 | vexLb<<2

	if hasFlag(e.flags, VEX_OP) && b1&0x7f == 0x61 && b2&0x80 == 0 {
		// 2-byte vex
		buf.Byte2(0xc5, (b1&0x80)|(b2&0x7f))
		return
	}

	if hasFlag(e.flags, VEX_OP) {
		buf.Byte(0xc4)
	} else {
		buf.Byte(0x8f)
	}

	buf.Byte2(byte(b1), byte(b2))
}
