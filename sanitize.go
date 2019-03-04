package x64

import "fmt"

// Go through the arguments, check for impossible to encode memory arguments, fill in immediate/displacement
// size information and return the effective address size
func sanitizeMemArgs(argc int, args *[4]Arg) (addrSize int8, err error) {
	addrSize = int8(-1)
	hasMem := false
	argSlice := args[:argc]
	for i, arg := range argSlice {
		mem, ok := arg.(Mem)
		if !ok {
			continue
		}
		if hasMem {
			return -1, fmt.Errorf("Only 1 memory argument is supported per instruction")
		}
		hasMem = true
		if addrSize, err = sanitizeMem(&mem); err != nil {
			return
		}
		if (mem.Base != 0 && mem.Base.Family() == REG_RIP) || (mem.Index != 0 && mem.Index.Family() == REG_RIP) {
			if mem.Disp == nil {
				mem.Disp = Rel32(0)
			} else if mem.Disp.width() != 4 {
				if ld, ok := mem.Disp.(LabelDisp); ok {
					mem.Disp = LabelDisp{l: ld.l, d: Rel32(ld.Int32())}
				} else if label, ok := mem.Disp.(LabelArg); ok {
					mem.Disp = Label32(uint16(label.label()))
				} else {
					mem.Disp = Rel32(mem.Disp.Int32())
				}
			}
		} else if mem.Disp != nil {
			dispsz := mem.Disp.width()
			if addrSize == 2 {
				if dispsz != 1 && dispsz != 2 {
					return addrSize, fmt.Errorf("Only 8/16-bit displacements are allowed with 16-bit addressing")
				}
			} else if dispsz != 0 && dispsz != 1 && dispsz != 4 {
				return addrSize, fmt.Errorf("Only 8/32-bit displacements are allowed without 64-bit addressing")
			}
		}
		argSlice[i] = mem
	}
	return
}

func resizeArgs(plen int, argp [8]byte, argc int, args *[4]Arg) (int8, error) {
	hasArg := false
	opSize := int8(-1)
	immSize := int8(-1)

	// scan arg-pattern:
	for pi, ai := 0, 0; pi+1 < plen && ai < argc; pi, ai = pi+2, ai+1 {
		arg := args[ai]

		switch v := arg.(type) {
		case Reg:
			hasArg = true
			width := int8(v.width())
			if opSize >= 0 && opSize != width {
				return -1, fmt.Errorf("Conflicting argument sizes")
			}
			opSize = width
		case Mem:
			hasArg = true
			if v.Index != 0 && (v.Index.Family() == REG_XMM || v.Index.Family() == REG_YMM) {
				v.Width = v.Index.Width()
				args[ai] = v
			}
			if v.Width != 0 {
				if opSize >= 0 && opSize != int8(v.Width) {
					return -1, fmt.Errorf("Conflicting argument sizes")
				}
				opSize = int8(v.Width)
			}
		default:
			if imm, ok := arg.(ImmArg); ok {
				width := int8(imm.width())
				if immSize >= 0 && immSize != width {
					return -1, fmt.Errorf("Conflicting argument sizes")
				}
				immSize = width
			} else if rel, ok := arg.(RelArg); ok {
				width := int8(rel.width())
				if opSize >= 0 && opSize != width {
					return -1, fmt.Errorf("Conflicting argument sizes")
				}
				opSize = width
			} else if label, ok := arg.(LabelArg); ok {
				width := int8(label.width())
				if opSize >= 0 && opSize != width {
					return -1, fmt.Errorf("Conflicting argument sizes")
				}
				opSize = width
			}
		}
	}

	if opSize >= 0 {
		refImmSize := opSize
		if opSize > 4 {
			refImmSize = 4
		}
		if immSize >= 0 && immSize > refImmSize {
			return -1, fmt.Errorf("Immediate size mismatch")
		}
		immSize = refImmSize
	} else if hasArg {
		return -1, fmt.Errorf("Unknown operand size")
	}

	for pi, ai := 0, 0; pi+1 < plen && ai < argc; pi, ai = pi+2, ai+1 {
		t, sz, arg := argp[pi], argp[pi+1], args[ai]
		size := uint8(0)

		switch {
		case sz == 'b':
			size = 1
		case sz == 'w':
			size = 2
		case t == 'k' || sz == 'd':
			size = 4
		case t == 'l' || sz == 'q':
			size = 8
		case sz == 'f':
			size = 10
		case sz == 'p':
			size = 6
		case sz == 'o':
			size = 16
		case sz == 'h':
			size = 32
		case sz == '0' && t == 'i':
			size = uint8(immSize)
		case sz == '0':
			size = uint8(opSize)
		case sz == '1':
			size = 1 // placeholder
		default:
			return -1, fmt.Errorf("Unexpected arg-pattern combination")
		}

		if imm, ok := arg.(ImmArg); ok {
			width := imm.width()
			if width != size {
				imm64 := imm.Int64()
				switch size {
				case 1:
					args[ai] = Imm8(int8(imm64))
				case 2:
					args[ai] = Imm16(int16(imm64))
				case 4:
					args[ai] = Imm32(int32(imm64))
				case 8:
					args[ai] = Imm64(imm64)
				}
			}
		} else if rel, ok := arg.(RelArg); ok {
			width := rel.width()
			if width != size {
				rel32 := rel.Int32()
				switch size {
				case 1:
					args[ai] = Rel8(int8(rel32))
				case 2:
					args[ai] = Rel16(int16(rel32))
				case 4:
					args[ai] = Rel32(int32(rel32))
				case 8:
					return -1, fmt.Errorf("Unexpected 64-bit displacement")
				}
			}
		} else if label, ok := arg.(LabelArg); ok {
			if ld, ok := label.(LabelDisp); ok {
				width := ld.width()
				if width != size {
					switch size {
					case 1:
						args[ai] = LabelDisp{l: ld.l, d: Rel8(int8(ld.Int32()))}
					case 2:
						args[ai] = LabelDisp{l: ld.l, d: Rel16(int16(ld.Int32()))}
					case 4:
						args[ai] = LabelDisp{l: ld.l, d: Rel32(ld.Int32())}
					case 8:
						return -1, fmt.Errorf("Unexpected 64-bit displacement for label reference")
					}
				}
			} else {
				width := label.width()
				if width != size {
					switch size {
					case 1:
						args[ai] = Label8(label.label())
					case 2:
						args[ai] = Label16(label.label())
					case 4:
						args[ai] = Label32(label.label())
					case 8:
						return -1, fmt.Errorf("Unexpected 64-bit displacement for label reference")
					}
				}
			}
		}
	}

	return opSize, nil
}

/// Validates that the base/index combination can actually be encoded and returns the effective address size.
/// If the address size can't be determined (purely displacement, or VSIB without base), -1 is returned.
func sanitizeMem(mem *Mem) (int8, error) {
	b, i, scale := mem.Base, mem.Index, mem.Scale
	if scale < 1 {
		scale = 1
		mem.Scale = scale
	}
	bsz, bfam := b.width(), b.Family()
	isz, ifam := i.width(), i.Family()
	// figure out the addressing size/mode used.
	// size can be 16, 32, or 64-bit.
	// mode can be legacy, rip-relative, or vsib
	// note that rip-relative and vsib only support 32 and 64-bit
	size := uint8(0)
	family := uint8(0)
	vsibMode := false

	// figure out the addressing mode and size
	switch {
	case b == 0 && i == 0:
		return -1, nil
	case b != 0 && i == 0:
		size, family = bsz, bfam
	case b == 0 && i != 0:
		size, family = isz, ifam
	default:
		switch {
		case bfam == ifam:
			if bsz != isz {
				return -1, fmt.Errorf("Registers of differing sizes for base/index: %v/%v", bsz, isz)
			}
			size, family = bsz, bfam
		// allow only vsib addressing
		case bfam == REG_XMM || bfam == REG_YMM:
			vsibMode, size, family = true, isz, ifam
		case ifam == REG_XMM || ifam == REG_YMM:
			vsibMode, size, family = true, bsz, bfam
		default:
			return -1, fmt.Errorf("Register combination not supported for base/index")
		}
	}

	if mem.Width == 0 {
		mem.Width = size
	}

	// filter out combinations that are impossible to encode
	switch family {
	case REG_RIP:
		if b != 0 && i != 0 {
			return -1, fmt.Errorf("Base and index registers not supported for RIP")
		}
	case REG_LEGACY:
		switch size {
		case 4, 8: // allowed
		case 2:
			if vsibMode {
				return -1, fmt.Errorf("16-bit addressing is unsupported with VSIB mode")
			}
		default:
			return -1, fmt.Errorf("Unsupported address size for legacy register: %v", size)
		}
	case REG_XMM, REG_YMM:
		if b != 0 && i != 0 {
			return -1, fmt.Errorf("Base and index registers not supported for XMM/YMM")
		}
	default:
		return -1, fmt.Errorf("Unsupported register family for memory operation: %v", family)
	}

	if family == REG_RIP {
		if scale != 1 {
			return -1, fmt.Errorf("Scale is not supported for RIP-relative encoding")
		}
		if i != 0 {
			mem.Base = i
			mem.Index = 0
		}
		return int8(size), nil
	}

	// VSIB without base
	if family == REG_XMM || family == REG_YMM {
		mem.Index = mem.Base
		mem.Base = 0
		mem.Scale = 1
		return -1, nil
	}

	// VSIB with base
	if vsibMode {
		// we're guaranteed that the other register is a legacy register, either DWORD or QWORD size
		// so we just have to check if an index/base swap is necessary
		if bfam == REG_XMM || bfam == REG_YMM {
			// try to swap if possible
			if i != 0 && scale == 1 {
				mem.Base, mem.Index = mem.Index, mem.Base
			} else {
				return -1, fmt.Errorf("VSIB addressing requires a general purpose register as base")
			}
		}
		return int8(size), nil
	}

	// 16-bit legacy addressing
	if size == 2 {
		// 16-bit addressing has no concept of index
		if i != 0 && scale != 1 {
			return -1, fmt.Errorf("16-bit addressing does not support a scaled index")
		}
		if b == 0 {
			b, i = i, 0
			bfam, ifam = b.Family(), i.Family()
		}

		encodedBase := Reg(0)
		bn, in := b.Num(), i.Num()
		if b != 0 && i != 0 && bfam == REG_LEGACY && ifam == REG_LEGACY {
			switch {
			case (bn == BX.Num() && in == SI.Num()) || (bn == SI.Num() && in == BX.Num()):
				encodedBase = AX
			case (bn == BX.Num() && in == DI.Num()) || (bn == DI.Num() && in == BX.Num()):
				encodedBase = CX
			case (bn == BP.Num() && in == SI.Num()) || (bn == SI.Num() && in == BP.Num()):
				encodedBase = DX
			case (bn == BP.Num() && in == DI.Num()) || (bn == DI.Num() && in == BP.Num()):
				encodedBase = BX
			}
		} else if b != 0 && i == 0 && bfam == REG_LEGACY {
			switch {
			case bn == SI.Num() && i == 0:
				encodedBase = SP
			case bn == DI.Num() && i == 0:
				encodedBase = BP
			case bn == BP.Num() && i == 0:
				encodedBase = SI
			case bn == BX.Num() && i == 0:
				encodedBase = DI
			}
		}

		mem.Base, mem.Index = encodedBase, i
		return int8(size), nil
	}

	// normal addressing

	// optimize indexes if a base is not present
	if b == 0 && i != 0 {
		switch scale {
		case 2, 3, 5, 9:
			b = i
			scale -= 1
		}
	}

	// RSP as index field can not be represented. Check if we can swap it with base
	if i != 0 {
		if i.Family() == REG_LEGACY && i.Num() == RSP.Num() {
			if (b.Family() == REG_LEGACY && b.Num() == RSP.Num()) || scale != 1 {
				return -1, fmt.Errorf("RSP cannot be used as index")
			}
			mem.Base, mem.Index, mem.Scale = i, b, 1
		}
	}

	// RSP or R12 as base without index (add an index so we escape into SIB)
	if b.Family() == REG_LEGACY && i == 0 && (b.Num() == RSP.Num() || b.Num() == R12.Num()) {
		mem.Scale = 1
		switch size {
		case 2:
			mem.Index = SP
		case 4:
			mem.Index = ESP
		default:
			mem.Index = RSP
		}
	}

	// RBP as base field just requires a mandatory MOD_DISP8, so we only process that at encoding time
	return int8(size), nil
}
