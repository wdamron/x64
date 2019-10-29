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
func (matcher *InstMatcher) extractArgs() error {
	argp := matcher.argp
	plen := len(argp)
	args := matcher.args
	argc := len(args)
	flags := matcher.enc.flags
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
			matcher._imms[immc] = arg
			immc++
		}
	}

	matcher.imms = matcher._imms[:immc]

	if regArg >= 0 {
		if regArg == 0 {
			matcher.r, matcher.m = regs[0], regs[1]
		} else {
			matcher.m, matcher.r = regs[0], regs[1]
		}
		return nil
	}

	switch regc {
	case 1:
		matcher.m = regs[0]
	case 2:
		if hasFlag(flags, ENC_MR) || memArg == 0 {
			matcher.m, matcher.r = regs[0], regs[1]
		} else if hasFlag(flags, ENC_VM) {
			matcher.v, matcher.m = regs[0], regs[1]
		} else {
			matcher.r, matcher.m = regs[0], regs[1]
		}
	case 3:
		if memArg == 1 {
			matcher.r, matcher.m, matcher.v = regs[0], regs[1], regs[2]
		} else if hasFlag(flags, ENC_VM) || memArg == 0 {
			matcher.m, matcher.v, matcher.r = regs[0], regs[1], regs[2]
		} else {
			matcher.r, matcher.v, matcher.m = regs[0], regs[1], regs[2]
		}
	case 4:
		if memArg == 2 {
			matcher.r, matcher.v, matcher.m, matcher.i = regs[0], regs[1], regs[2], regs[3]
		} else {
			matcher.r, matcher.v, matcher.i, matcher.m = regs[0], regs[1], regs[2], regs[3]
		}
	}

	return nil
}
