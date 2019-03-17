package x64

import (
	. "github.com/wdamron/x64/internal/flags"
)

// Operand order:
//
// if there's a memory/reg operand, this operand goes into modrm.r/m
// if there's a segment/control/debug register, it goes into reg.
//
// default argument encoding order is as follows:
// no encoding flag: m, rm, rvm, rvim
// ENC_MR:              mr, rmv, rvmi
// ENC_VM:              vm, mvr
// these can also be chosen based on the location of a memory argument (except for vm)
func (a *Assembler) extractArgs() error {
	argp := a.inst.argp
	plen := len(argp)
	args := a.inst.args
	argc := len(args)
	flags := a.inst.enc.flags
	ext := &a.inst.ext
	memArg := -1
	regArg := -1
	var regs [4]Arg
	regc := 0
	immc := 0

	// scan arg-pattern:
	for pi, ai := 0, 0; pi+1 < plen && ai < argc; pi, ai = pi+2, ai+1 {
		t, arg := argp[pi], args[ai]

		switch t {
		case 'm', 'u', 'v', 'w', 'k', 'l':
			if memArg >= 0 {
				panic("Multiple memory arguments in format string")
			}
			memArg = regc
			regs[regc] = arg
			regc++
		case 'f', 'x', 'r', 'y', 'b':
			regs[regc] = arg
			regc++
		case 'c', 'd', 's':
			if regArg >= 0 {
				panic("multiple segment, debug or control registers in format string")
			}
			regArg = regc
			regs[regc] = arg
			regc++
		case 'i', 'o':
			ext._imms[immc] = arg
			immc++
		}
	}

	ext.imms = ext._imms[:immc]

	if regArg >= 0 {
		if regArg == 0 {
			ext.r, ext.m = regs[0], regs[1]
		} else {
			ext.m, ext.r = regs[0], regs[1]
		}
		return nil
	}

	switch regc {
	case 1:
		ext.m = regs[0]
	case 2:
		if hasFlag(flags, ENC_MR) || memArg == 0 {
			ext.m, ext.r = regs[0], regs[1]
		} else if hasFlag(flags, ENC_VM) {
			ext.v, ext.m = regs[0], regs[1]
		} else {
			ext.r, ext.m = regs[0], regs[1]
		}
	case 3:
		if memArg == 1 {
			ext.r, ext.m, ext.v = regs[0], regs[1], regs[2]
		} else if hasFlag(flags, ENC_VM) || memArg == 0 {
			ext.m, ext.v, ext.r = regs[0], regs[1], regs[2]
		} else {
			ext.r, ext.v, ext.m = regs[0], regs[1], regs[2]
		}
	case 4:
		if memArg == 2 {
			ext.r, ext.v, ext.m, ext.i = regs[0], regs[1], regs[2], regs[3]
		} else {
			ext.r, ext.v, ext.i, ext.m = regs[0], regs[1], regs[2], regs[3]
		}
	}

	return nil
}
