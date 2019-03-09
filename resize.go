package x64

import "fmt"

// Resize all arguments to match the arg-pattern for the matched encoding
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
				if immSize >= 0 && immSize != width {
					return -1, fmt.Errorf("Conflicting argument sizes")
				}
				immSize = width
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
