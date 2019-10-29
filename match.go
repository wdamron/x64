package x64

import (
	"errors"

	"github.com/wdamron/x64/feats"
)

// ErrNoMatch will be returned if no matching instruction-encoding is found while encoding an instruction.
var ErrNoMatch = errors.New("No matching instruction-encoding was found")

// Operand type/size patterns
//
// i : immediate
// o : instruction offset
//
// m : memory
// k : vsib addressing, 32 bit result, size determines xmm or ymm
// l : vsib addressing, 64 bit result, size determines xmm or ymm
//
// r : legacy reg
// f : fp reg
// x : mmx reg
// y : xmm/ymm reg
// s : segment reg
// c : control reg
// d : debug reg
// b : bound reg
//
// v : r and m
// u : x and m
// w : y and m
//
// A ... P: match rax - r15
// Q ... V: match es, cs, ss, ds, fs, gs
// W: matches CR8
// X: matches st0
//
// b, w, d, q, o, h match a byte, word, doubleword, quadword, octword and hexadecword
// p matches a PWORD (10 bytes)
// f matches an FWORD (6 bytes)
// 0/* matches all possible sizes for this operand (w/d for i, w/d/q for r/v, o/h for y/w and everything for m)
// 1/_ matches a lack of size, only useful in combination with m
func (matcher *InstMatcher) matchInst(feats feats.Feature, startOffset uint16) bool {
	inst := matcher.inst
	args := matcher.args
	argc := len(args)
	o := inst.offset() + startOffset
	c := uint16(inst.count()) - startOffset
SEARCH:
	for ei, e := range encs[o : o+c] {
		if e.feats&feats != e.feats {
			continue SEARCH
		}
		p := argpFormats[e.argp]
		pl := 0
		for _, b := range p[:] {
			if b == 0 {
				break
			}
			pl++
		}
		if pl/2 != argc {
			continue
		}

		// scan arg-pattern:
		for pi, ai := 0, 0; pi+1 < pl && ai < argc; pi, ai = pi+2, ai+1 {
			t, sz, arg := p[pi], p[pi+1], args[ai]

			argsz := arg.width()

			// check type
			switch t {
			case 'i': // immediate
				if !isImm(arg) {
					continue SEARCH
				}
			case 'o': // displacement
				if !isDisp(arg) {
					continue SEARCH
				}
			case 'W': // CR8
				if r, ok := arg.(Reg); !ok || r != CR8 {
					continue SEARCH
				}
			case 'X': // F0
				if r, ok := arg.(Reg); !ok || r != F0 {
					continue SEARCH
				}
			case 'r', 'v': // legacy reg or memory
				switch argv := arg.(type) {
				case Reg:
					if argv.Family() != REG_LEGACY && argv.Family() != REG_HIGHBYTE {
						continue SEARCH
					}
				case memArgPlaceholder:
					mem := matcher.mem
					if t != 'v' || (mem.Index != 0 && (mem.Index.Family() == REG_XMM || mem.Index.Family() == REG_YMM)) {
						continue SEARCH
					}
					argsz = mem.width()
				default:
					continue SEARCH
				}
			case 'x', 'u': // mmx reg or memory
				switch argv := arg.(type) {
				case Reg:
					if argv.Family() != REG_MMX {
						continue SEARCH
					}
				case memArgPlaceholder:
					mem := matcher.mem
					if t != 'u' || (mem.Index != 0 && (mem.Index.Family() == REG_XMM || mem.Index.Family() == REG_YMM)) {
						continue SEARCH
					}
					argsz = mem.width()
				default:
					continue SEARCH
				}
			case 'y', 'w': // xmm/ymm reg or memory
				switch argv := arg.(type) {
				case Reg:
					if argv.Family() != REG_XMM && argv.Family() != REG_YMM {
						continue SEARCH
					}
				case memArgPlaceholder:
					mem := matcher.mem
					if t != 'w' || (mem.Index != 0 && (mem.Index.Family() == REG_XMM || mem.Index.Family() == REG_YMM)) {
						continue SEARCH
					}
					argsz = mem.width()
				default:
					continue SEARCH
				}
			case 'm': // memory
				if matcher.memOffset != ai {
					continue SEARCH
				}
				m := matcher.mem
				if m.Index != 0 && (m.Index.Family() == REG_XMM || m.Index.Family() == REG_YMM) {
					continue SEARCH
				}
				argsz = m.width()
			case 'f': // fp reg
				if r, ok := arg.(Reg); !ok || r.Family() != REG_FP {
					continue SEARCH
				}
			case 's': // segment reg
				if r, ok := arg.(Reg); !ok || r.Family() != REG_SEGMENT {
					continue SEARCH
				}
			case 'c': // control reg
				if r, ok := arg.(Reg); !ok || r.Family() != REG_CONTROL {
					continue SEARCH
				}
			case 'd': // debug reg
				if r, ok := arg.(Reg); !ok || r.Family() != REG_DEBUG {
					continue SEARCH
				}
			case 'b': // bound reg
				continue SEARCH // TODO(?): bound registers aren't currently handled
			// k : vsib addressing, 32 bit result, size determines xmm or ymm
			// l : vsib addressing, 64 bit result, size determines xmm or ymm
			case 'k', 'l':
				if matcher.memOffset != ai {
					continue SEARCH
				}
				m := matcher.mem
				if m.Index.Family() != REG_XMM && m.Index.Family() != REG_YMM {
					continue SEARCH
				}
				argsz = m.Index.width()
			default:
				switch {
				case t >= 'A' && t <= 'P': // rax - r15 (fixed reg)
					if r, ok := arg.(Reg); !ok || r.Family() != REG_LEGACY || byte(r.Num()) != t-'A' {
						continue SEARCH
					}
				case t >= 'Q' && t <= 'V': // es, cs, ss, ds, fs, gs (fixed reg)
					if r, ok := arg.(Reg); !ok || r.Family() != REG_SEGMENT || byte(r.Num()) != t-'Q' {
						continue SEARCH
					}
				default:
					continue SEARCH
				}
			}

			// check size
			switch sz {
			case 'b':
				if argsz > 1 {
					continue SEARCH
				}
			case 'w':
				if argsz > 2 {
					continue SEARCH
				}
			case 'd':
				if argsz > 4 {
					continue SEARCH
				}
			case 'q':
				if argsz > 8 {
					continue SEARCH
				}
			case 'f':
				if argsz != 10 {
					continue SEARCH
				}
			case 'p':
				if argsz != 6 {
					continue SEARCH
				}
			case 'o':
				if argsz != 16 {
					continue SEARCH
				}
			case 'h':
				if argsz != 32 {
					continue SEARCH
				}
			case '0': // matches all possible sizes for this operand (w/d for i, w/d/q for r/v, o/h for y/w and everything for m)
				switch t {
				case 'i': // immediate
					if argsz != 2 && argsz != 4 && argsz != 8 {
						continue SEARCH
					}
				// k : vsib addressing, 32 bit result, size determines xmm or ymm
				// l : vsib addressing, 64 bit result, size determines xmm or ymm
				// y : xmm/ymm reg
				// w : xmm/ymm reg or memory
				case 'k', 'l', 'y', 'w':
					if argsz != 16 && argsz != 32 {
						continue SEARCH
					}
				case 'm': // memory
					// match
				case 'r', 'v': // legacy reg or r/m
					if argsz != 2 && argsz != 4 && argsz != 8 {
						continue SEARCH
					}
				default:
					switch {
					case t >= 'A' && t <= 'P': // rax - r15 (fixed reg)
						if argsz != 2 && argsz != 4 && argsz != 8 {
							continue SEARCH
						}
					default:
						continue SEARCH
					}
				}
			case '1': // matches a lack of size, only useful in combination with m
				if t != 'm' {
					continue SEARCH
				}
			default:
				continue SEARCH
			}
		}

		if e.offset() != uint8(ei)+uint8(startOffset) || e.instid() != inst.Id() {
			panic("unexpected encoding at offset")
		}

		// all arguments match for the current encoding
		matcher.encId = uint(o) + uint(ei) + uint(startOffset)
		matcher.enc = e
		matcher.argp = p[:pl]
		return true
	}

	matcher.enc = enc{}
	return false
}
