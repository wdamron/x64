package main

// go build -o gen gen.go && rm -f ../x86.generated.go && ./gen > ../x86.generated.go

import (
	"fmt"
	. "github.com/wdamron/x64/flags"
	"os"
	"sort"
	"strings"
	"text/template"
)

func rank(mne string) int {
	hp := strings.HasPrefix
	hs := strings.HasSuffix
	switch {
	case mne == "push" || mne == "pop" || mne == "pause" || hp(mne, "push") || hp(mne, "pop") || hp(mne, "mov") || hp(mne, "prefetch"):
		return 0
	case hp(mne, "sha") || hp(mne, "xsha") || hp(mne, "aes") || hp(mne, "xcrypt") || (mne[0] == 'x' && mne != "xor" && !hp(mne, "xor")):
		return 1
	case mne[0] == 'v':
		return 5
	case mne[0] == 'p':
		return 4
	case mne[0] == 'f':
		return 2
	case mne[0] != 'p' && (hs(mne, "ps") || hs(mne, "pd")):
		return 3
	default:
		return 0
	}
}

// Encoding:
//
// mnemonics:
// * uint32 constants (1507 are available)
// * [0..14] bits are uint16 offset into encodings array
// * [16..20] bits specify the number of available encodings for the mnemonic
// * [21..31] bits identify the unique mnemonic
//
// encodings:
// * [2535]encoding
// * encoding is a 16-byte struct:
//   * arg-pattern: byte (254 possible combinations)
//   * reg + opcode-length: byte
//     * [0..3] bits identify the reg
//     * [4..6] bits specify the opcode length (0 -> 1-byte, 1 -> 2-byte, 2 -> 3-byte, 3 -> 4-byte)
//   * opcode: [4]byte
//   * flags: uint32
//   * feats: uint32
//   * mnemonic: uint16
//     * [0..10] bits identify the unique mnemonic (reverse mapping to the mnemonic)
//     * [11..15] bits identify the offset of this encoding w.r.t. the starting offset for the mnemonic within the encodings array
//
// mnemonics + encodings tables consume ~88KB
func main() {
	var ms []mnemonic
	pset := make(map[string]int, 256)
	for mne, specs := range opMap {
		// TODO: existing flags will conflict with these
		if mne == "prefetchwt1" || mne == "invpcid" {
			continue
		}
		x64specs := make([]spec, 0, len(specs))
		for _, spec := range specs {
			if spec.flags&X86_ONLY != 0 {
				continue
			}
			pset[spec.pattern] = -1
			x64specs = append(x64specs, spec)
		}
		if len(x64specs) == 0 {
			continue
		}
		ms = append(ms, mnemonic{mne, x64specs, -1, -1})
	}
	ps := make([]string, 0, len(pset))
	for p, _ := range pset {
		ps = append(ps, p)
	}

	sort.Slice(ms, func(i, j int) bool {
		si, sj := ms[i], ms[j]
		if si.mne == sj.mne {
			return false
		}
		ri, rj := rank(si.mne), rank(sj.mne)
		if ri < rj {
			return true
		}
		if ri > rj {
			return false
		}
		return si.mne < sj.mne
	})
	sort.Slice(ps, func(i, j int) bool {
		pi, pj := ps[i], ps[j]
		return len(pi) < len(pj) || (len(pi) == len(pj) && pi < pj)
	})
	var sps []spec
	for i, m := range ms {
		ms[i].i = i + 1 // i will use 1-based indexes since 0 represents an invalid instruction
		ms[i].offset = len(sps)
		for _, sp := range m.specs {
			sps = append(sps, sp)
		}
	}
	for pi, p := range ps {
		i := pset[p]
		delete(pset, p)
		p = strings.Replace(p, "*", "0", -1)
		p = strings.Replace(p, "!", "1", -1)
		p = strings.Replace(p, "?", "2", -1)
		delete(pset, p)
		pset[p] = i + 1
		ps[pi] = p
	}
	type TM struct {
		Name, Value string
	}
	type TE struct {
		Argp     string
		Regoplen string
		Op       string
		Flags    string
		Feats    string
		Mne      string
		MneName  string
		Offset   string
	}
	tms := make([]TM, len(ms))
	tes := make([]TE, len(sps))
	mflat := ""
	mtab := ""
	for i, m := range ms {
		tms[i] = TM{
			Name: strings.ToUpper(m.mne),
			// m.i will use 1-based indexes since 0 represents an invalid instruction
			Value: fmt.Sprintf("%v<<21 | %v<<16 | %v", m.i, len(m.specs), m.offset),
		}
		if i > 0 {
			mtab += ", "
		}
		mtab += fmt.Sprintf("%d", len(mflat))
		mflat += tms[i].Name
		off := m.offset
		for j, sp := range m.specs {
			op := ""
			for i, b := range sp.op {
				if i > 0 {
					op += ", "
				}
				op += fmt.Sprintf("%#x", b)
			}
			for i := len(sp.op); i < 4; i++ {
				op += ", 0x00"
			}
			reg := sp.reg
			if reg < 0 {
				reg = 15
			}
			flags := ""
			if sp.flags == 0 {
				flags = "0"
			} else {
				for f := uint32(0); f < 32; f++ {
					if sp.flags&(1<<f) != 0 {
						if flags != "" {
							flags += " | "
						}
						flags += FlagName(1 << f)
					}
				}
			}
			feats := ""
			if sp.feats == 0 {
				feats = "0"
			} else {
				for f := uint32(0); f < 32; f++ {
					if sp.feats&(1<<f) != 0 {
						if feats != "" {
							feats += " | "
						}
						feats += FeatName(1 << f)
					}
				}
			}
			tes[off+j] = TE{
				Argp:     "argp_" + cleanArgp(sp.pattern),
				Regoplen: fmt.Sprintf("%v<<4 | %v", len(sp.op), reg),
				Op:       op,
				Flags:    flags,
				Feats:    feats,
				Mne:      fmt.Sprintf("%v<<11 | %v", j, m.i),
				MneName:  m.mne,
				Offset:   fmt.Sprintf("%v", int(off+j)),
			}
		}
	}
	//len(ms) = 1507
	//len(ps) = 254
	//len(sps) = 2535
	pfs := make([]string, len(ps))
	for i, p := range ps {
		pf := "[8]byte{"
		for i := 0; i < len(p); i++ {
			if i > 0 {
				pf += ", "
			}
			pf += fmt.Sprintf("'%s'", string(p[i]))
		}
		if len(p) == 0 {
			pf += "0, 0, 0, 0, 0, 0, 0, 0"
		} else {
			for i := 0; i < 8-len(p); i++ {
				pf += ", 0"
			}
		}
		pf += "}"
		pfs[i] = pf
	}
	ct := template.Must(template.New("constants-x86").Parse(constantsTemplate))
	cli := ""
	for _, arg := range os.Args {
		switch arg {
		case "patterns", "mnemonics", "encodings":
			cli = arg
		}
	}
	if cli == "" {
		fmt.Fprintln(os.Stderr, "missing rendering arg (patterns|mnemonics|encodings)")
		os.Exit(1)
	}
	err := ct.Execute(os.Stdout, struct {
		Patterns       []string
		PatternFormats []string
		Mnemonics      []TM
		MnemonicsFlat  string
		NameOffsets    string
		Encodings      []TE
		Cli            string
	}{
		Patterns:       ps,
		PatternFormats: pfs,
		Mnemonics:      tms,
		MnemonicsFlat:  mflat,
		NameOffsets:    mtab,
		Encodings:      tes,
		Cli:            cli,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func cleanArgp(p string) string {
	p = strings.Replace(p, "*", "0", -1)
	p = strings.Replace(p, "!", "1", -1)
	p = strings.Replace(p, "?", "2", -1)
	return p
}

const constantsTemplate = `package x64

// THIS FILE IS AUTOMATICALLY GENERATED. DO NOT EDIT!
// go build -o ./gen/gen ./gen/gen.go && ./gen/gen {{ .Cli }} > ./x86.generated.go

{{ if (eq .Cli "patterns") }}
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
// 0 matches all possible sizes for this operand (w/d for i, w/d/q for r/v, o/h for y/w and everything for m)
// 1 matches a lack of size, only useful in combination with m
const (
	{{ range $i, $p := .Patterns }}argp_{{ $p }}{{ if (eq $i 0) }} uint8 = iota{{ end }}
	{{ end }}
)

var argpFormats = [...][8]byte{
	{{ range $p := .PatternFormats }}{{ $p }},
	{{ end }}
}
{{ end }}
{{ if (eq .Cli "mnemonics") }}
// Instruction-mnemonic constants:
//
// [0..12] bits are uint16 offset into encodings array
//
// [16..20] bits specify the number of available encodings for the mnemonic
//
// [21..31] bits identify the unique mnemonic
const (
	{{ range $m := .Mnemonics }}{{ $m.Name }} Inst = {{ $m.Value }}
	{{ end }}
)

// Instruction-mnemonic names:

const instNames = "{{ .MnemonicsFlat }}"

var instNameOffsets = [...]uint16{ {{ .NameOffsets }} }

{{ end }}{{ if (eq .Cli "encodings") }}

import . "github.com/wdamron/x64/flags"

// Instruction-encoding table:
//
// * Encoding spec is a 16-byte struct:
//     * opcode: [4]byte
//     * flags: uint32
//     * feats: uint32
//     * mnemonic: uint16
//       * [0..10] bits identify the unique mnemonic (reverse mapping to the mnemonic)
//       * [11..15] bits identify the offset of this encoding w.r.t. the starting offset for the mnemonic within the encodings array
//     * reg + opcode-length: byte
//       * [0..3] bits identify the reg
//       * [4..6] bits specify the opcode length (0 -> 1-byte, 1 -> 2-byte, 2 -> 3-byte, 3 -> 4-byte)
//     * arg-pattern: byte (254 possible combinations)
var encs = [...]enc{
	{{ range $e := .Encodings }}enc{ [4]byte{ {{ $e.Op }} }, {{ $e.Flags }}, {{ $e.Feats }}, {{ $e.Mne }}, {{ $e.Regoplen }}, {{ $e.Argp }}, }, // {{ $e.MneName }} ({{ $e.Offset }})
	{{ end }}
}
{{ end }}
`

type mnemonic struct {
	mne    string
	specs  []spec
	i      int
	offset int
}

type specs []spec

type spec struct {
	pattern string
	op      op
	reg     int8
	flags   uint32
	feats   uint32
}

type op []byte

// Patterns:
// 20 possible operand types
// 11 possible operand sizes
// 254 unique patterns (across all registered instructions)
//
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
// * matches all possible sizes for this operand (w/d for i, w/d/q for r/v, o/h for y/w and everything for m)
// ! matches a lack of size, only useful in combination with m
// ? matches any size and doesn't participate in the operand size calculation

// any-reg placeholder
const X int8 = -1

var opMap = map[string]specs{
	"aaa": {
		spec{"", op{0x37}, X, X86_ONLY, X64_IMPLICIT},
	},
	"aad": {
		spec{"", op{0xD5, 0x0A}, X, X86_ONLY, X64_IMPLICIT},
	},
	"aam": {
		spec{"", op{0xD4, 0x0A}, X, X86_ONLY, X64_IMPLICIT},
	},
	"aas": {
		spec{"", op{0x3F}, X, X86_ONLY, X64_IMPLICIT},
	},
	"adc": {
		spec{"Abib", op{0x14}, X, DEFAULT, X64_IMPLICIT},
		spec{"mbib", op{0x80}, 2, LOCK, X64_IMPLICIT},
		spec{"mbrb", op{0x10}, X, LOCK | ENC_MR, X64_IMPLICIT},
		spec{"rbib", op{0x80}, 2, DEFAULT, X64_IMPLICIT},
		spec{"rbrb", op{0x10}, X, ENC_MR, X64_IMPLICIT},
		spec{"rbvb", op{0x12}, X, DEFAULT, X64_IMPLICIT},
		spec{"r*ib", op{0x83}, 2, AUTO_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"A*i*", op{0x15}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"m*i*", op{0x81}, 2, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*ib", op{0x83}, 2, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*r*", op{0x11}, X, AUTO_SIZE | LOCK | ENC_MR, X64_IMPLICIT},
		spec{"r*i*", op{0x81}, 2, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*r*", op{0x11}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
		spec{"r*v*", op{0x13}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"adcx": {
		spec{"rqvq", op{0x0F, 0x38, 0xF6}, X, WITH_REXW | PREF_66, X64_IMPLICIT},
	},
	"add": {
		spec{"Abib", op{0x04}, X, DEFAULT, X64_IMPLICIT},
		spec{"mbib", op{0x80}, 0, LOCK, X64_IMPLICIT},
		spec{"mbrb", op{0x00}, X, LOCK | ENC_MR, X64_IMPLICIT},
		spec{"rbib", op{0x80}, 0, DEFAULT, X64_IMPLICIT},
		spec{"rbrb", op{0x00}, X, ENC_MR, X64_IMPLICIT},
		spec{"rbvb", op{0x02}, X, DEFAULT, X64_IMPLICIT},
		spec{"r*ib", op{0x83}, 0, AUTO_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"A*i*", op{0x05}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"m*i*", op{0x81}, 0, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*ib", op{0x83}, 0, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*r*", op{0x01}, X, AUTO_SIZE | LOCK | ENC_MR, X64_IMPLICIT},
		spec{"r*i*", op{0x81}, 0, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*r*", op{0x01}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
		spec{"r*v*", op{0x03}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"addpd": {
		spec{"yowo", op{0x0F, 0x58}, X, PREF_66, SSE2},
	},
	"addps": {
		spec{"yowo", op{0x0F, 0x58}, X, DEFAULT, SSE},
	},
	"addsd": {
		spec{"yomq", op{0x0F, 0x58}, X, PREF_F2, SSE2},
		spec{"yoyo", op{0x0F, 0x58}, X, PREF_F2, SSE2},
	},
	"addss": {
		spec{"yomd", op{0x0F, 0x58}, X, PREF_F3, SSE},
		spec{"yoyo", op{0x0F, 0x58}, X, PREF_F3, SSE},
	},
	"addsubpd": {
		spec{"yowo", op{0x0F, 0xD0}, X, PREF_66, SSE3},
	},
	"addsubps": {
		spec{"yowo", op{0x0F, 0xD0}, X, PREF_F2, SSE3},
	},
	"adox": {
		spec{"rqvq", op{0x0F, 0x38, 0xF6}, X, WITH_REXW | PREF_F3, X64_IMPLICIT},
	},
	"aesdec": {
		spec{"yowo", op{0x0F, 0x38, 0xDE}, X, PREF_66, SSE},
	},
	"aesdeclast": {
		spec{"yowo", op{0x0F, 0x38, 0xDF}, X, PREF_66, SSE},
	},
	"aesenc": {
		spec{"yowo", op{0x0F, 0x38, 0xDC}, X, PREF_66, SSE},
	},
	"aesenclast": {
		spec{"yowo", op{0x0F, 0x38, 0xDD}, X, PREF_66, SSE},
	},
	"aesimc": {
		spec{"yowo", op{0x0F, 0x38, 0xDB}, X, PREF_66, SSE},
	},
	"aeskeygenassist": {
		spec{"yowoib", op{0x0F, 0x3A, 0xDF}, X, PREF_66, SSE},
	},
	"and": {
		spec{"Abib", op{0x24}, X, DEFAULT, X64_IMPLICIT},
		spec{"mbib", op{0x80}, 4, LOCK, X64_IMPLICIT},
		spec{"mbrb", op{0x20}, X, LOCK | ENC_MR, X64_IMPLICIT},
		spec{"rbib", op{0x80}, 4, DEFAULT, X64_IMPLICIT},
		spec{"rbrb", op{0x20}, X, ENC_MR, X64_IMPLICIT},
		spec{"rbvb", op{0x22}, X, DEFAULT, X64_IMPLICIT},
		spec{"r*ib", op{0x83}, 4, AUTO_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"A*i*", op{0x25}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"m*i*", op{0x81}, 4, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*ib", op{0x83}, 4, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*r*", op{0x21}, X, AUTO_SIZE | LOCK | ENC_MR, X64_IMPLICIT},
		spec{"r*i*", op{0x81}, 4, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*r*", op{0x21}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
		spec{"r*v*", op{0x23}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"andn": {
		spec{"r*r*v*", op{0x02, 0xF2}, X, VEX_OP | AUTO_REXW, BMI1},
	},
	"andnpd": {
		spec{"yowo", op{0x0F, 0x55}, X, PREF_66, SSE2},
	},
	"andnps": {
		spec{"yowo", op{0x0F, 0x55}, X, DEFAULT, SSE},
	},
	"andpd": {
		spec{"yowo", op{0x0F, 0x54}, X, PREF_66, SSE2},
	},
	"andps": {
		spec{"yowo", op{0x0F, 0x54}, X, DEFAULT, SSE},
	},
	"arpl": {
		spec{"vwrw", op{0x63}, X, X86_ONLY, X64_IMPLICIT},
	},
	"bextr": {
		spec{"r*v*id", op{0x10, 0x10}, X, XOP_OP | AUTO_REXW, TBM},
		spec{"r*v*r*", op{0x02, 0xF7}, X, VEX_OP | AUTO_REXW | ENC_MR, BMI1},
	},
	"blcfill": {
		spec{"r*v*", op{0x09, 0x01}, 1, XOP_OP | AUTO_REXW | ENC_VM, TBM},
	},
	"blci": {
		spec{"r*v*", op{0x09, 0x02}, 6, XOP_OP | AUTO_REXW | ENC_VM, TBM},
	},
	"blcic": {
		spec{"r*v*", op{0x09, 0x01}, 5, XOP_OP | AUTO_REXW | ENC_VM, TBM},
	},
	"blcmsk": {
		spec{"r*v*", op{0x09, 0x02}, 1, XOP_OP | AUTO_REXW | ENC_VM, TBM},
	},
	"blcs": {
		spec{"r*v*", op{0x09, 0x01}, 3, XOP_OP | AUTO_REXW | ENC_VM, TBM},
	},
	"blendpd": {
		spec{"yomqib", op{0x0F, 0x3A, 0x0D}, X, PREF_66, SSE41},
		spec{"yoyoib", op{0x0F, 0x3A, 0x0D}, X, PREF_66, SSE41},
	},
	"blendps": {
		spec{"yomqib", op{0x0F, 0x3A, 0x0C}, X, PREF_66, SSE41},
		spec{"yoyoib", op{0x0F, 0x3A, 0x0C}, X, PREF_66, SSE41},
	},
	"blendvpd": {
		spec{"yomq", op{0x0F, 0x38, 0x15}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x15}, X, PREF_66, SSE41},
	},
	"blendvps": {
		spec{"yomq", op{0x0F, 0x38, 0x14}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x14}, X, PREF_66, SSE41},
	},
	"blsfill": {
		spec{"r*v*", op{0x09, 0x01}, 2, XOP_OP | AUTO_REXW | ENC_VM, TBM},
	},
	"blsi": {
		spec{"r*v*", op{0x02, 0xF3}, 3, VEX_OP | AUTO_REXW | ENC_VM, BMI1},
	},
	"blsic": {
		spec{"r*v*", op{0x09, 0x01}, 6, XOP_OP | AUTO_REXW | ENC_VM, TBM},
	},
	"blsmsk": {
		spec{"r*v*", op{0x02, 0xF3}, 2, VEX_OP | AUTO_REXW | ENC_VM, BMI1},
	},
	"blsr": {
		spec{"r*v*", op{0x02, 0xF3}, 1, VEX_OP | AUTO_REXW | ENC_VM, BMI1},
	},
	"bound": {
		spec{"r*m!", op{0x62}, X, AUTO_SIZE | X86_ONLY, X64_IMPLICIT},
	},
	"bndcl": {
		spec{"bom!", op{0x0F, 0x1A}, X, PREF_F3, MPX},
		spec{"borq", op{0x0F, 0x1A}, X, PREF_F3, MPX},
	},
	"bndcn": {
		spec{"bom!", op{0x0F, 0x1B}, X, PREF_F2, MPX},
		spec{"borq", op{0x0F, 0x1B}, X, PREF_F2, MPX},
	},
	"bndcu": {
		spec{"bom!", op{0x0F, 0x1A}, X, PREF_F2, MPX},
		spec{"borq", op{0x0F, 0x1A}, X, PREF_F2, MPX},
	},
	"bndldx": {
		spec{"bom!", op{0x0F, 0x1A}, X, ENC_MIB, MPX},
	},
	"bndmk": {
		spec{"bom!", op{0x0F, 0x1B}, X, ENC_MIB | PREF_F3, MPX},
	},
	"bndmov": {
		spec{"bobo", op{0x0F, 0x1A}, X, PREF_66, MPX},
		spec{"bobo", op{0x0F, 0x1B}, X, ENC_MR | PREF_66, MPX},
		spec{"bom!", op{0x0F, 0x1A}, X, PREF_66, MPX},
		spec{"m!bo", op{0x0F, 0x1B}, X, ENC_MR | PREF_66, MPX},
	},
	"bndstx": {
		spec{"m!bo", op{0x0F, 0x1B}, X, ENC_MR | ENC_MIB, MPX},
	},
	"bsf": {
		spec{"r*v*", op{0x0F, 0xBC}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"bsr": {
		spec{"r*v*", op{0x0F, 0xBD}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"bswap": {
		spec{"r*", op{0x0F, 0xC8}, X, AUTO_REXW | SHORT_ARG, X64_IMPLICIT},
	},
	"bt": {
		spec{"v*ib", op{0x0F, 0xBA}, 4, AUTO_SIZE, X64_IMPLICIT},
		spec{"v*r*", op{0x0F, 0xA3}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
	},
	"btc": {
		spec{"r*ib", op{0x0F, 0xBA}, 7, AUTO_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"m*ib", op{0x0F, 0xBA}, 7, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*r*", op{0x0F, 0xBB}, X, AUTO_SIZE | LOCK | ENC_MR, X64_IMPLICIT},
		spec{"r*r*", op{0x0F, 0xBB}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
	},
	"btr": {
		spec{"r*ib", op{0x0F, 0xBA}, 6, AUTO_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"m*ib", op{0x0F, 0xBA}, 6, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*r*", op{0x0F, 0xB3}, X, AUTO_SIZE | LOCK | ENC_MR, X64_IMPLICIT},
		spec{"r*r*", op{0x0F, 0xB3}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
	},
	"bts": {
		spec{"r*ib", op{0x0F, 0xBA}, 5, AUTO_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"m*ib", op{0x0F, 0xBA}, 5, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*r*", op{0x0F, 0xAB}, X, AUTO_SIZE | LOCK | ENC_MR, X64_IMPLICIT},
		spec{"r*r*", op{0x0F, 0xAB}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
	},
	"bzhi": {
		spec{"r*v*r*", op{0x02, 0xF5}, X, VEX_OP | AUTO_REXW | ENC_MR, BMI2},
	},
	"cbw": {
		spec{"", op{0x98}, X, WORD_SIZE, X64_IMPLICIT},
	},
	"cdq": {
		spec{"", op{0x99}, X, DEFAULT, X64_IMPLICIT},
	},
	"cdqe": {
		spec{"", op{0x98}, X, WITH_REXW, X64_IMPLICIT},
	},
	"clac": {
		spec{"", op{0x0F, 0x01, 0xCA}, X, DEFAULT, X64_IMPLICIT},
	},
	"clc": {
		spec{"", op{0xF8}, X, DEFAULT, X64_IMPLICIT},
	},
	"cld": {
		spec{"", op{0xFC}, X, DEFAULT, X64_IMPLICIT},
	},
	"clflush": {
		spec{"mb", op{0x0F, 0xAE}, 7, DEFAULT, SSE2},
	},
	"clgi": {
		spec{"", op{0x0F, 0x01, 0xDD}, X, DEFAULT, VMX | AMD},
	},
	"cli": {
		spec{"", op{0xFA}, X, DEFAULT, X64_IMPLICIT},
	},
	"clts": {
		spec{"", op{0x0F, 0x06}, X, DEFAULT, X64_IMPLICIT},
	},
	"clzero": {
		spec{"", op{0x0F, 0x01, 0xFC}, X, DEFAULT, AMD},
	},
	"cmc": {
		spec{"", op{0xF5}, X, DEFAULT, X64_IMPLICIT},
	},
	"cmp": {
		spec{"Abib", op{0x3C}, X, DEFAULT, X64_IMPLICIT},
		spec{"rbvb", op{0x3A}, X, DEFAULT, X64_IMPLICIT},
		spec{"vbib", op{0x80}, 7, DEFAULT, X64_IMPLICIT},
		spec{"vbrb", op{0x38}, X, ENC_MR, X64_IMPLICIT},
		spec{"A*i*", op{0x3D}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*v*", op{0x3B}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"v*i*", op{0x81}, 7, AUTO_SIZE, X64_IMPLICIT},
		spec{"v*ib", op{0x83}, 7, AUTO_SIZE, X64_IMPLICIT},
		spec{"v*r*", op{0x39}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
	},
	"cmpeqpd": {
		spec{"yowo", op{0x0F, 0xC2, 0x00}, X, PREF_66 | IMM_OP, SSE2},
	},
	"cmpeqps": {
		spec{"yowo", op{0x0F, 0xC2, 0x00}, X, IMM_OP, SSE},
	},
	"cmpeqsd": {
		spec{"yomq", op{0x0F, 0xC2, 0x00}, X, PREF_F2 | IMM_OP, SSE2},
		spec{"yoyo", op{0x0F, 0xC2, 0x00}, X, PREF_F2 | IMM_OP, SSE2},
	},
	"cmpeqss": {
		spec{"yomd", op{0x0F, 0xC2, 0x00}, X, PREF_F3 | IMM_OP, SSE},
		spec{"yoyo", op{0x0F, 0xC2, 0x00}, X, PREF_F3 | IMM_OP, SSE},
	},
	"cmplepd": {
		spec{"yowo", op{0x0F, 0xC2, 0x02}, X, IMM_OP | PREF_66, SSE2},
	},
	"cmpleps": {
		spec{"yowo", op{0x0F, 0xC2, 0x02}, X, IMM_OP, SSE},
	},
	"cmplesd": {
		spec{"yomq", op{0x0F, 0xC2, 0x02}, X, PREF_F2 | IMM_OP, SSE2},
		spec{"yoyo", op{0x0F, 0xC2, 0x02}, X, PREF_F2 | IMM_OP, SSE2},
	},
	"cmpless": {
		spec{"yomd", op{0x0F, 0xC2, 0x02}, X, PREF_F3 | IMM_OP, SSE},
		spec{"yoyo", op{0x0F, 0xC2, 0x02}, X, PREF_F3 | IMM_OP, SSE},
	},
	"cmpltpd": {
		spec{"yowo", op{0x0F, 0xC2, 0x01}, X, IMM_OP | PREF_66, SSE2},
	},
	"cmpltps": {
		spec{"yowo", op{0x0F, 0xC2, 0x01}, X, IMM_OP, SSE},
	},
	"cmpltsd": {
		spec{"yomq", op{0x0F, 0xC2, 0x01}, X, PREF_F2 | IMM_OP, SSE2},
		spec{"yoyo", op{0x0F, 0xC2, 0x01}, X, PREF_F2 | IMM_OP, SSE2},
	},
	"cmpltss": {
		spec{"yomd", op{0x0F, 0xC2, 0x01}, X, IMM_OP | PREF_F3, SSE},
		spec{"yoyo", op{0x0F, 0xC2, 0x01}, X, IMM_OP | PREF_F3, SSE},
	},
	"cmpneqpd": {
		spec{"yowo", op{0x0F, 0xC2, 0x04}, X, PREF_66 | IMM_OP, SSE2},
	},
	"cmpneqps": {
		spec{"yowo", op{0x0F, 0xC2, 0x04}, X, IMM_OP, SSE},
	},
	"cmpneqsd": {
		spec{"yomq", op{0x0F, 0xC2, 0x04}, X, PREF_F2 | IMM_OP, SSE2},
		spec{"yoyo", op{0x0F, 0xC2, 0x04}, X, PREF_F2 | IMM_OP, SSE2},
	},
	"cmpneqss": {
		spec{"yomd", op{0x0F, 0xC2, 0x04}, X, IMM_OP | PREF_F3, SSE},
		spec{"yoyo", op{0x0F, 0xC2, 0x04}, X, IMM_OP | PREF_F3, SSE},
	},
	"cmpnlepd": {
		spec{"yowo", op{0x0F, 0xC2, 0x06}, X, IMM_OP | PREF_66, SSE2},
	},
	"cmpnleps": {
		spec{"yowo", op{0x0F, 0xC2, 0x06}, X, IMM_OP, SSE},
	},
	"cmpnlesd": {
		spec{"yomq", op{0x0F, 0xC2, 0x06}, X, PREF_F2 | IMM_OP, SSE2},
		spec{"yoyo", op{0x0F, 0xC2, 0x06}, X, PREF_F2 | IMM_OP, SSE2},
	},
	"cmpnless": {
		spec{"yomd", op{0x0F, 0xC2, 0x06}, X, IMM_OP | PREF_F3, SSE},
		spec{"yoyo", op{0x0F, 0xC2, 0x06}, X, IMM_OP | PREF_F3, SSE},
	},
	"cmpnltpd": {
		spec{"yowo", op{0x0F, 0xC2, 0x05}, X, PREF_66 | IMM_OP, SSE2},
	},
	"cmpnltps": {
		spec{"yowo", op{0x0F, 0xC2, 0x05}, X, IMM_OP, SSE},
	},
	"cmpnltsd": {
		spec{"yomq", op{0x0F, 0xC2, 0x05}, X, IMM_OP | PREF_F2, SSE2},
		spec{"yoyo", op{0x0F, 0xC2, 0x05}, X, IMM_OP | PREF_F2, SSE2},
	},
	"cmpnltss": {
		spec{"yomd", op{0x0F, 0xC2, 0x05}, X, PREF_F3 | IMM_OP, SSE},
		spec{"yoyo", op{0x0F, 0xC2, 0x05}, X, PREF_F3 | IMM_OP, SSE},
	},
	"cmpordpd": {
		spec{"yowo", op{0x0F, 0xC2, 0x07}, X, IMM_OP | PREF_66, SSE2},
	},
	"cmpordps": {
		spec{"yowo", op{0x0F, 0xC2, 0x07}, X, IMM_OP, SSE},
	},
	"cmpordsd": {
		spec{"yomq", op{0x0F, 0xC2, 0x07}, X, PREF_F2 | IMM_OP, SSE2},
		spec{"yoyo", op{0x0F, 0xC2, 0x07}, X, PREF_F2 | IMM_OP, SSE2},
	},
	"cmpordss": {
		spec{"yomd", op{0x0F, 0xC2, 0x07}, X, IMM_OP | PREF_F3, SSE},
		spec{"yoyo", op{0x0F, 0xC2, 0x07}, X, IMM_OP | PREF_F3, SSE},
	},
	"cmppd": {
		spec{"yowoib", op{0x0F, 0xC2}, X, PREF_66, SSE2},
	},
	"cmpps": {
		spec{"yom!ib", op{0x0F, 0xC2}, X, DEFAULT, SSE},
		spec{"yoyoib", op{0x0F, 0xC2}, X, DEFAULT, SSE},
	},
	"cmpsb": {
		spec{"", op{0xA6}, X, REPE, X64_IMPLICIT},
	},
	"cmpsd": {
		spec{"", op{0xA7}, X, REPE, X64_IMPLICIT},
		spec{"yowoib", op{0x0F, 0xC2}, X, PREF_F2, SSE2},
	},
	"cmpsq": {
		spec{"", op{0xA7}, X, REPE | WITH_REXW, X64_IMPLICIT},
	},
	"cmpss": {
		spec{"yom!ib", op{0x0F, 0xC2}, X, PREF_F3, SSE},
		spec{"yoyoib", op{0x0F, 0xC2}, X, PREF_F3, SSE},
	},
	"cmpsw": {
		spec{"", op{0xA7}, X, REPE | WORD_SIZE, X64_IMPLICIT},
	},
	"cmpunordpd": {
		spec{"yowo", op{0x0F, 0xC2, 0x03}, X, PREF_66 | IMM_OP, SSE2},
	},
	"cmpunordps": {
		spec{"yowo", op{0x0F, 0xC2, 0x03}, X, IMM_OP, SSE},
	},
	"cmpunordsd": {
		spec{"yomq", op{0x0F, 0xC2, 0x03}, X, PREF_F2 | IMM_OP, SSE2},
		spec{"yoyo", op{0x0F, 0xC2, 0x03}, X, PREF_F2 | IMM_OP, SSE2},
	},
	"cmpunordss": {
		spec{"yomd", op{0x0F, 0xC2, 0x03}, X, PREF_F3 | IMM_OP, SSE},
		spec{"yoyo", op{0x0F, 0xC2, 0x03}, X, PREF_F3 | IMM_OP, SSE},
	},
	"cmpxchg": {
		spec{"mbrb", op{0x0F, 0xB0}, X, LOCK | ENC_MR, X64_IMPLICIT},
		spec{"rbrb", op{0x0F, 0xB0}, X, ENC_MR, X64_IMPLICIT},
		spec{"m*r*", op{0x0F, 0xB1}, X, AUTO_SIZE | LOCK | ENC_MR, X64_IMPLICIT},
		spec{"r*r*", op{0x0F, 0xB1}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
	},
	"cmpxchg16b": {
		spec{"mo", op{0x0F, 0xC7}, 1, LOCK | WITH_REXW, X64_IMPLICIT},
	},
	"cmpxchg8b": {
		spec{"mq", op{0x0F, 0xC7}, 1, LOCK, X64_IMPLICIT},
	},
	"comisd": {
		spec{"yomq", op{0x0F, 0x2F}, X, PREF_66, SSE2},
		spec{"yoyo", op{0x0F, 0x2F}, X, PREF_66, SSE2},
	},
	"comiss": {
		spec{"yomd", op{0x0F, 0x2F}, X, DEFAULT, SSE},
		spec{"yoyo", op{0x0F, 0x2F}, X, DEFAULT, SSE},
	},
	"cpu_read": {
		spec{"", op{0x0F, 0x3D}, X, DEFAULT, CYRIX},
	},
	"cpu_write": {
		spec{"", op{0x0F, 0x3C}, X, DEFAULT, CYRIX},
	},
	"cpuid": {
		spec{"", op{0x0F, 0xA2}, X, DEFAULT, X64_IMPLICIT},
	},
	"cqo": {
		spec{"", op{0x99}, X, WITH_REXW, X64_IMPLICIT},
	},
	"cvtdq2pd": {
		spec{"yomq", op{0x0F, 0xE6}, X, PREF_F3, SSE2},
		spec{"yoyo", op{0x0F, 0xE6}, X, PREF_F3, SSE2},
	},
	"cvtdq2ps": {
		spec{"yowo", op{0x0F, 0x5B}, X, DEFAULT, SSE2},
	},
	"cvtpd2dq": {
		spec{"yowo", op{0x0F, 0xE6}, X, PREF_F2, SSE2},
	},
	"cvtpd2pi": {
		spec{"xqwo", op{0x0F, 0x2D}, X, PREF_66, SSE2},
	},
	"cvtpd2ps": {
		spec{"yowo", op{0x0F, 0x5A}, X, PREF_66, SSE2},
	},
	"cvtpi2pd": {
		spec{"youq", op{0x0F, 0x2A}, X, PREF_66, SSE2},
	},
	"cvtpi2ps": {
		spec{"youq", op{0x0F, 0x2A}, X, DEFAULT, MMX | SSE},
	},
	"cvtps2dq": {
		spec{"yowo", op{0x0F, 0x5B}, X, PREF_66, SSE2},
	},
	"cvtps2pd": {
		spec{"yomq", op{0x0F, 0x5A}, X, DEFAULT, SSE2},
		spec{"yoyo", op{0x0F, 0x5A}, X, DEFAULT, SSE2},
	},
	"cvtps2pi": {
		spec{"xqmq", op{0x0F, 0x2D}, X, DEFAULT, SSE | MMX},
		spec{"xqyo", op{0x0F, 0x2D}, X, DEFAULT, SSE | MMX},
	},
	"cvtsd2si": {
		spec{"rdmq", op{0x0F, 0x2D}, X, PREF_F2, SSE2},
		spec{"rdyo", op{0x0F, 0x2D}, X, PREF_F2, SSE2},
		spec{"rqmq", op{0x0F, 0x2D}, X, WITH_REXW | PREF_F2, SSE2},
		spec{"rqyo", op{0x0F, 0x2D}, X, WITH_REXW | PREF_F2, SSE2},
	},
	"cvtsd2ss": {
		spec{"yomq", op{0x0F, 0x5A}, X, PREF_F2, SSE2},
		spec{"yoyo", op{0x0F, 0x5A}, X, PREF_F2, SSE2},
	},
	"cvtsi2sd": {
		spec{"yovd", op{0x0F, 0x2A}, X, PREF_F2, SSE2},
		spec{"yovq", op{0x0F, 0x2A}, X, WITH_REXW | PREF_F2, SSE2},
	},
	"cvtsi2ss": {
		spec{"yovd", op{0x0F, 0x2A}, X, PREF_F3, SSE},
		spec{"yovq", op{0x0F, 0x2A}, X, WITH_REXW | PREF_F3, SSE},
	},
	"cvtss2sd": {
		spec{"yomd", op{0x0F, 0x5A}, X, PREF_F3, SSE2},
		spec{"yoyo", op{0x0F, 0x5A}, X, PREF_F3, SSE2},
	},
	"cvtss2si": {
		spec{"rdmd", op{0x0F, 0x2D}, X, PREF_F3, SSE},
		spec{"rdyo", op{0x0F, 0x2D}, X, PREF_F3, SSE},
		spec{"rqmd", op{0x0F, 0x2D}, X, WITH_REXW | PREF_F3, SSE},
		spec{"rqyo", op{0x0F, 0x2D}, X, WITH_REXW | PREF_F3, SSE},
	},
	"cvttpd2dq": {
		spec{"yowo", op{0x0F, 0xE6}, X, PREF_66, SSE2},
	},
	"cvttpd2pi": {
		spec{"xqwo", op{0x0F, 0x2C}, X, PREF_66, SSE2},
	},
	"cvttps2dq": {
		spec{"yowo", op{0x0F, 0x5B}, X, PREF_F3, SSE2},
	},
	"cvttps2pi": {
		spec{"xqmq", op{0x0F, 0x2C}, X, DEFAULT, SSE | MMX},
		spec{"xqyo", op{0x0F, 0x2C}, X, DEFAULT, SSE | MMX},
	},
	"cvttsd2si": {
		spec{"rdmq", op{0x0F, 0x2C}, X, PREF_F2, SSE2},
		spec{"rdyo", op{0x0F, 0x2C}, X, PREF_F2, SSE2},
		spec{"rqmq", op{0x0F, 0x2C}, X, WITH_REXW | PREF_F2, SSE2},
		spec{"rqyo", op{0x0F, 0x2C}, X, WITH_REXW | PREF_F2, SSE2},
	},
	"cvttss2si": {
		spec{"rdmd", op{0x0F, 0x2C}, X, PREF_F3, SSE},
		spec{"rdyo", op{0x0F, 0x2C}, X, PREF_F3, SSE},
		spec{"rqmd", op{0x0F, 0x2C}, X, WITH_REXW | PREF_F3, SSE},
		spec{"rqyo", op{0x0F, 0x2C}, X, WITH_REXW | PREF_F3, SSE},
	},
	"cwd": {
		spec{"", op{0x99}, X, WORD_SIZE, X64_IMPLICIT},
	},
	"cwde": {
		spec{"", op{0x98}, X, DEFAULT, X64_IMPLICIT},
	},
	"daa": {
		spec{"", op{0x27}, X, X86_ONLY, X64_IMPLICIT},
	},
	"das": {
		spec{"", op{0x2F}, X, X86_ONLY, X64_IMPLICIT},
	},
	"dec": {
		spec{"mb", op{0xFE}, 1, LOCK, X64_IMPLICIT},
		spec{"rb", op{0xFE}, 1, DEFAULT, X64_IMPLICIT},
		spec{"m*", op{0xFF}, 1, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"r*", op{0x48}, 0, X86_ONLY | SHORT_ARG, X64_IMPLICIT},
		spec{"r*", op{0xFF}, 1, AUTO_SIZE, X64_IMPLICIT},
	},
	"div": {
		spec{"vb", op{0xF6}, 6, DEFAULT, X64_IMPLICIT},
		spec{"v*", op{0xF7}, 6, AUTO_SIZE, X64_IMPLICIT},
	},
	"divpd": {
		spec{"yowo", op{0x0F, 0x5E}, X, PREF_66, SSE2},
	},
	"divps": {
		spec{"yowo", op{0x0F, 0x5E}, X, DEFAULT, SSE},
	},
	"divsd": {
		spec{"yomq", op{0x0F, 0x5E}, X, PREF_F2, SSE2},
		spec{"yoyo", op{0x0F, 0x5E}, X, PREF_F2, SSE2},
	},
	"divss": {
		spec{"yomd", op{0x0F, 0x5E}, X, PREF_F3, SSE},
		spec{"yoyo", op{0x0F, 0x5E}, X, PREF_F3, SSE},
	},
	"dmint": {
		spec{"", op{0x0F, 0x39}, X, DEFAULT, CYRIX},
	},
	"dppd": {
		spec{"yomqib", op{0x0F, 0x3A, 0x41}, X, PREF_66, SSE41},
		spec{"yoyoib", op{0x0F, 0x3A, 0x41}, X, PREF_66, SSE41},
	},
	"dpps": {
		spec{"yomqib", op{0x0F, 0x3A, 0x40}, X, PREF_66, SSE41},
		spec{"yoyoib", op{0x0F, 0x3A, 0x40}, X, PREF_66, SSE41},
	},
	"emms": {
		spec{"", op{0x0F, 0x77}, X, DEFAULT, MMX},
	},
	"enter": {
		spec{"iwib", op{0xC8}, X, DEFAULT, X64_IMPLICIT},
	},
	"extractps": {
		spec{"rqyoib", op{0x0F, 0x3A, 0x17}, X, WITH_REXW | ENC_MR | PREF_66, SSE41},
		spec{"vdyoib", op{0x0F, 0x3A, 0x17}, X, ENC_MR | PREF_66, SSE41},
	},
	"extrq": {
		spec{"yoibib", op{0x0F, 0x78}, 0, PREF_66, SSE4A | AMD},
		spec{"yoyo", op{0x0F, 0x79}, X, PREF_66, SSE4A | AMD},
	},
	"f2xm1": {
		spec{"", op{0xD9, 0xF0}, X, DEFAULT, FPU},
	},
	"fabs": {
		spec{"", op{0xD9, 0xE1}, X, DEFAULT, FPU},
	},
	"fadd": {
		spec{"", op{0xDE, 0xC1}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xD8, 0xC0}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xD8, 0xC0}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDC, 0xC0}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDC, 0xC0}, X, SHORT_ARG, FPU},
		spec{"md", op{0xD8}, 0, EXACT_SIZE, FPU},
		spec{"mq", op{0xDC}, 0, EXACT_SIZE, FPU},
	},
	"faddp": {
		spec{"", op{0xDE, 0xC1}, X, DEFAULT, FPU},
		spec{"fp", op{0xDE, 0xC0}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDE, 0xC0}, X, SHORT_ARG, FPU},
	},
	"fbld": {
		spec{"m!", op{0xDF}, 4, DEFAULT, FPU},
	},
	"fbstp": {
		spec{"m!", op{0xDF}, 6, DEFAULT, FPU},
	},
	"fchs": {
		spec{"", op{0xD9, 0xE0}, X, DEFAULT, FPU},
	},
	"fclex": {
		spec{"", op{0x9B, 0xDB, 0xE2}, X, DEFAULT, FPU},
	},
	"fcmovb": {
		spec{"", op{0xDA, 0xC1}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xDA, 0xC0}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xDA, 0xC0}, X, SHORT_ARG, FPU},
	},
	"fcmovbe": {
		spec{"", op{0xDA, 0xD1}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xDA, 0xD0}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xDA, 0xD0}, X, SHORT_ARG, FPU},
	},
	"fcmove": {
		spec{"", op{0xDA, 0xC9}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xDA, 0xC8}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xDA, 0xC8}, X, SHORT_ARG, FPU},
	},
	"fcmovnb": {
		spec{"", op{0xDB, 0xC1}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xDB, 0xC0}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xDB, 0xC0}, X, SHORT_ARG, FPU},
	},
	"fcmovnbe": {
		spec{"", op{0xDB, 0xD1}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xDB, 0xD0}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xDB, 0xD0}, X, SHORT_ARG, FPU},
	},
	"fcmovne": {
		spec{"", op{0xDB, 0xC9}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xDB, 0xC8}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xDB, 0xC8}, X, SHORT_ARG, FPU},
	},
	"fcmovnu": {
		spec{"", op{0xDB, 0xD9}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xDB, 0xD8}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xDB, 0xD8}, X, SHORT_ARG, FPU},
	},
	"fcmovu": {
		spec{"", op{0xDA, 0xD9}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xDA, 0xD8}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xDA, 0xD8}, X, SHORT_ARG, FPU},
	},
	"fcom": {
		spec{"", op{0xD8, 0xD1}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xD8, 0xD0}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xD8, 0xD0}, X, SHORT_ARG, FPU},
		spec{"md", op{0xD8}, 2, EXACT_SIZE, FPU},
		spec{"mq", op{0xDC}, 2, EXACT_SIZE, FPU},
	},
	"fcomi": {
		spec{"", op{0xDB, 0xF1}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xDB, 0xF0}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xDB, 0xF0}, X, SHORT_ARG, FPU},
	},
	"fcomip": {
		spec{"", op{0xDF, 0xF1}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xDF, 0xF0}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xDF, 0xF0}, X, SHORT_ARG, FPU},
	},
	"fcomp": {
		spec{"", op{0xD8, 0xD9}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xD8, 0xD8}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xD8, 0xD8}, X, SHORT_ARG, FPU},
		spec{"md", op{0xD8}, 3, EXACT_SIZE, FPU},
		spec{"mq", op{0xDC}, 3, EXACT_SIZE, FPU},
	},
	"fcompp": {
		spec{"", op{0xDE, 0xD9}, X, DEFAULT, FPU},
	},
	"fcos": {
		spec{"", op{0xD9, 0xFF}, X, DEFAULT, FPU},
	},
	"fdecstp": {
		spec{"", op{0xD9, 0xF6}, X, DEFAULT, FPU},
	},
	"fdisi": {
		spec{"", op{0x9B, 0xDB, 0xE1}, X, DEFAULT, FPU},
	},
	"fdiv": {
		spec{"", op{0xDE, 0xF9}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xD8, 0xF0}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xD8, 0xF0}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDC, 0xF8}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDC, 0xF8}, X, SHORT_ARG, FPU},
		spec{"md", op{0xD8}, 6, EXACT_SIZE, FPU},
		spec{"mq", op{0xDC}, 6, EXACT_SIZE, FPU},
	},
	"fdivp": {
		spec{"", op{0xDE, 0xF9}, X, DEFAULT, FPU},
		spec{"fp", op{0xDE, 0xF8}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDE, 0xF8}, X, SHORT_ARG, FPU},
	},
	"fdivr": {
		spec{"", op{0xDE, 0xF1}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xD8, 0xF8}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xD8, 0xF8}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDC, 0xF0}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDC, 0xF0}, X, SHORT_ARG, FPU},
		spec{"md", op{0xD8}, 7, EXACT_SIZE, FPU},
		spec{"mq", op{0xDC}, 7, EXACT_SIZE, FPU},
	},
	"fdivrp": {
		spec{"", op{0xDE, 0xF1}, X, DEFAULT, FPU},
		spec{"fp", op{0xDE, 0xF0}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDE, 0xF0}, X, SHORT_ARG, FPU},
	},
	"femms": {
		spec{"", op{0x0F, 0x0E}, X, DEFAULT, TDNOW},
	},
	"feni": {
		spec{"", op{0x9B, 0xDB, 0xE0}, X, DEFAULT, FPU},
	},
	"ffree": {
		spec{"", op{0xDD, 0xC1}, X, DEFAULT, FPU},
		spec{"fp", op{0xDD, 0xC0}, X, SHORT_ARG, FPU},
	},
	"fiadd": {
		spec{"md", op{0xDA}, 0, EXACT_SIZE, FPU},
		spec{"mw", op{0xDE}, 0, DEFAULT, FPU},
	},
	"ficom": {
		spec{"md", op{0xDA}, 2, EXACT_SIZE, FPU},
		spec{"mw", op{0xDE}, 2, DEFAULT, FPU},
	},
	"ficomp": {
		spec{"md", op{0xDA}, 3, EXACT_SIZE, FPU},
		spec{"mw", op{0xDE}, 3, DEFAULT, FPU},
	},
	"fidiv": {
		spec{"md", op{0xDA}, 6, EXACT_SIZE, FPU},
		spec{"mw", op{0xDE}, 6, DEFAULT, FPU},
	},
	"fidivr": {
		spec{"md", op{0xDA}, 7, EXACT_SIZE, FPU},
		spec{"mw", op{0xDE}, 7, DEFAULT, FPU},
	},
	"fild": {
		spec{"md", op{0xDB}, 0, EXACT_SIZE, FPU},
		spec{"mq", op{0xDF}, 5, EXACT_SIZE, FPU},
		spec{"mw", op{0xDF}, 0, DEFAULT, FPU},
	},
	"fimul": {
		spec{"md", op{0xDA}, 1, EXACT_SIZE, FPU},
		spec{"mw", op{0xDE}, 1, DEFAULT, FPU},
	},
	"fincstp": {
		spec{"", op{0xD9, 0xF7}, X, DEFAULT, FPU},
	},
	"finit": {
		spec{"", op{0x9B, 0xDB, 0xE3}, X, DEFAULT, FPU},
	},
	"fist": {
		spec{"md", op{0xDB}, 2, EXACT_SIZE, FPU},
		spec{"mw", op{0xDF}, 2, DEFAULT, FPU},
	},
	"fistp": {
		spec{"md", op{0xDB}, 3, EXACT_SIZE, FPU},
		spec{"mq", op{0xDF}, 7, EXACT_SIZE, FPU},
		spec{"mw", op{0xDF}, 3, DEFAULT, FPU},
	},
	"fisttp": {
		spec{"md", op{0xDB}, 1, EXACT_SIZE, FPU},
		spec{"mq", op{0xDD}, 1, EXACT_SIZE, FPU},
		spec{"mw", op{0xDF}, 1, DEFAULT, FPU},
	},
	"fisub": {
		spec{"md", op{0xDA}, 4, EXACT_SIZE, FPU},
		spec{"mw", op{0xDE}, 4, DEFAULT, FPU},
	},
	"fisubr": {
		spec{"md", op{0xDA}, 5, EXACT_SIZE, FPU},
		spec{"mw", op{0xDE}, 5, DEFAULT, FPU},
	},
	"fld": {
		spec{"", op{0xD9, 0xC1}, X, DEFAULT, FPU},
		spec{"fp", op{0xD9, 0xC0}, X, SHORT_ARG, FPU},
		spec{"md", op{0xD9}, 0, EXACT_SIZE, FPU},
		spec{"mp", op{0xDB}, 5, EXACT_SIZE, FPU},
		spec{"mq", op{0xDD}, 0, EXACT_SIZE, FPU},
	},
	"fld1": {
		spec{"", op{0xD9, 0xE8}, X, DEFAULT, FPU},
	},
	"fldcw": {
		spec{"mw", op{0xD9}, 5, DEFAULT, FPU},
	},
	"fldenv": {
		spec{"m!", op{0xD9}, 4, DEFAULT, FPU},
	},
	"fldl2e": {
		spec{"", op{0xD9, 0xEA}, X, DEFAULT, FPU},
	},
	"fldl2t": {
		spec{"", op{0xD9, 0xE9}, X, DEFAULT, FPU},
	},
	"fldlg2": {
		spec{"", op{0xD9, 0xEC}, X, DEFAULT, FPU},
	},
	"fldln2": {
		spec{"", op{0xD9, 0xED}, X, DEFAULT, FPU},
	},
	"fldpi": {
		spec{"", op{0xD9, 0xEB}, X, DEFAULT, FPU},
	},
	"fldz": {
		spec{"", op{0xD9, 0xEE}, X, DEFAULT, FPU},
	},
	"fmul": {
		spec{"", op{0xDE, 0xC9}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xD8, 0xC8}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xD8, 0xC8}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDC, 0xC8}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDC, 0xC8}, X, SHORT_ARG, FPU},
		spec{"md", op{0xD8}, 1, EXACT_SIZE, FPU},
		spec{"mq", op{0xDC}, 1, EXACT_SIZE, FPU},
	},
	"fmulp": {
		spec{"", op{0xDE, 0xC9}, X, DEFAULT, FPU},
		spec{"fp", op{0xDE, 0xC8}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDE, 0xC8}, X, SHORT_ARG, FPU},
	},
	"fnclex": {
		spec{"", op{0xDB, 0xE2}, X, DEFAULT, FPU},
	},
	"fndisi": {
		spec{"", op{0xDB, 0xE1}, X, DEFAULT, FPU},
	},
	"fneni": {
		spec{"", op{0xDB, 0xE0}, X, DEFAULT, FPU},
	},
	"fninit": {
		spec{"", op{0xDB, 0xE3}, X, DEFAULT, FPU},
	},
	"fnop": {
		spec{"", op{0xD9, 0xD0}, X, DEFAULT, FPU},
	},
	"fnsave": {
		spec{"m!", op{0xDD}, 6, DEFAULT, FPU},
	},
	"fnstcw": {
		spec{"mw", op{0xD9}, 7, DEFAULT, FPU},
	},
	"fnstenv": {
		spec{"m!", op{0xD9}, 6, DEFAULT, FPU},
	},
	"fnstsw": {
		spec{"Aw", op{0xDF, 0xE0}, X, DEFAULT, FPU},
		spec{"mw", op{0xDD}, 7, DEFAULT, FPU},
	},
	"fpatan": {
		spec{"", op{0xD9, 0xF3}, X, DEFAULT, FPU},
	},
	"fprem": {
		spec{"", op{0xD9, 0xF8}, X, DEFAULT, FPU},
	},
	"fprem1": {
		spec{"", op{0xD9, 0xF5}, X, DEFAULT, FPU},
	},
	"fptan": {
		spec{"", op{0xD9, 0xF2}, X, DEFAULT, FPU},
	},
	"frndint": {
		spec{"", op{0xD9, 0xFC}, X, DEFAULT, FPU},
	},
	"frstor": {
		spec{"m!", op{0xDD}, 4, DEFAULT, FPU},
	},
	"fsave": {
		spec{"m!", op{0x9B, 0xDD}, 6, DEFAULT, FPU},
	},
	"fscale": {
		spec{"", op{0xD9, 0xFD}, X, DEFAULT, FPU},
	},
	"fsetpm": {
		spec{"", op{0xDB, 0xE4}, X, DEFAULT, FPU},
	},
	"fsin": {
		spec{"", op{0xD9, 0xFE}, X, DEFAULT, FPU},
	},
	"fsincos": {
		spec{"", op{0xD9, 0xFB}, X, DEFAULT, FPU},
	},
	"fsqrt": {
		spec{"", op{0xD9, 0xFA}, X, DEFAULT, FPU},
	},
	"fst": {
		spec{"", op{0xDD, 0xD1}, X, DEFAULT, FPU},
		spec{"fp", op{0xDD, 0xD0}, X, SHORT_ARG, FPU},
		spec{"md", op{0xD9}, 2, EXACT_SIZE, FPU},
		spec{"mq", op{0xDD}, 2, EXACT_SIZE, FPU},
	},
	"fstcw": {
		spec{"mw", op{0x9B, 0xD9}, 7, DEFAULT, FPU},
	},
	"fstenv": {
		spec{"m!", op{0x9B, 0xD9}, 6, DEFAULT, FPU},
	},
	"fstp": {
		spec{"", op{0xDD, 0xD9}, X, DEFAULT, FPU},
		spec{"fp", op{0xDD, 0xD8}, X, SHORT_ARG, FPU},
		spec{"md", op{0xD9}, 3, EXACT_SIZE, FPU},
		spec{"mp", op{0xDB}, 7, EXACT_SIZE, FPU},
		spec{"mq", op{0xDD}, 3, EXACT_SIZE, FPU},
	},
	"fstsw": {
		spec{"Aw", op{0x9B, 0xDF, 0xE0}, X, DEFAULT, FPU},
		spec{"mw", op{0x9B, 0xDD}, 7, DEFAULT, FPU},
	},
	"fsub": {
		spec{"", op{0xDE, 0xE9}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xD8, 0xE0}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xD8, 0xE0}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDC, 0xE8}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDC, 0xE8}, X, SHORT_ARG, FPU},
		spec{"md", op{0xD8}, 4, EXACT_SIZE, FPU},
		spec{"mq", op{0xDC}, 4, EXACT_SIZE, FPU},
	},
	"fsubp": {
		spec{"", op{0xDE, 0xE9}, X, DEFAULT, FPU},
		spec{"fp", op{0xDE, 0xE8}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDE, 0xE8}, X, SHORT_ARG, FPU},
	},
	"fsubr": {
		spec{"", op{0xDE, 0xE1}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xD8, 0xE8}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xD8, 0xE8}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDC, 0xE0}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDC, 0xE0}, X, SHORT_ARG, FPU},
		spec{"md", op{0xD8}, 5, EXACT_SIZE, FPU},
		spec{"mq", op{0xDC}, 5, EXACT_SIZE, FPU},
	},
	"fsubrp": {
		spec{"", op{0xDE, 0xE1}, X, DEFAULT, FPU},
		spec{"fp", op{0xDE, 0xE0}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xDE, 0xE0}, X, SHORT_ARG, FPU},
	},
	"ftst": {
		spec{"", op{0xD9, 0xE4}, X, DEFAULT, FPU},
	},
	"fucom": {
		spec{"", op{0xDD, 0xE1}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xDD, 0xE0}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xDD, 0xE0}, X, SHORT_ARG, FPU},
	},
	"fucomi": {
		spec{"", op{0xDB, 0xE9}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xDB, 0xE8}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xDB, 0xE8}, X, SHORT_ARG, FPU},
	},
	"fucomip": {
		spec{"", op{0xDF, 0xE9}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xDF, 0xE8}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xDF, 0xE8}, X, SHORT_ARG, FPU},
	},
	"fucomp": {
		spec{"", op{0xDD, 0xE9}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xDD, 0xE8}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xDD, 0xE8}, X, SHORT_ARG, FPU},
	},
	"fucompp": {
		spec{"", op{0xDA, 0xE9}, X, DEFAULT, FPU},
	},
	"fwait": {
		spec{"", op{0x9B}, X, DEFAULT, X64_IMPLICIT},
	},
	"fxam": {
		spec{"", op{0xD9, 0xE5}, X, DEFAULT, FPU},
	},
	"fxch": {
		spec{"", op{0xD9, 0xC9}, X, DEFAULT, FPU},
		spec{"Xpfp", op{0xD9, 0xC8}, X, SHORT_ARG, FPU},
		spec{"fp", op{0xD9, 0xC8}, X, SHORT_ARG, FPU},
		spec{"fpXp", op{0xD9, 0xC8}, X, SHORT_ARG, FPU},
	},
	"fxrstor": {
		spec{"m!", op{0x0F, 0xAE}, 1, DEFAULT, SSE | FPU},
	},
	"fxrstor64": {
		spec{"m!", op{0x0F, 0xAE}, 1, WITH_REXW, FPU | SSE},
	},
	"fxsave": {
		spec{"m!", op{0x0F, 0xAE}, 0, DEFAULT, FPU | SSE},
	},
	"fxsave64": {
		spec{"m!", op{0x0F, 0xAE}, 0, WITH_REXW, SSE | FPU},
	},
	"fxtract": {
		spec{"", op{0xD9, 0xF4}, X, DEFAULT, FPU},
	},
	"fyl2x": {
		spec{"", op{0xD9, 0xF1}, X, DEFAULT, FPU},
	},
	"fyl2xp1": {
		spec{"", op{0xD9, 0xF9}, X, DEFAULT, FPU},
	},
	"getsec": {
		spec{"", op{0x0F, 0x37}, X, DEFAULT, X64_IMPLICIT},
	},
	"haddpd": {
		spec{"yowo", op{0x0F, 0x7C}, X, PREF_66, SSE3},
	},
	"haddps": {
		spec{"yowo", op{0x0F, 0x7C}, X, PREF_F2, SSE3},
	},
	"hlt": {
		spec{"", op{0xF4}, X, DEFAULT, X64_IMPLICIT},
	},
	"hsubpd": {
		spec{"yowo", op{0x0F, 0x7D}, X, PREF_66, SSE3},
	},
	"hsubps": {
		spec{"yowo", op{0x0F, 0x7D}, X, PREF_F2, SSE3},
	},
	"icebp": {
		spec{"", op{0xF1}, X, DEFAULT, X64_IMPLICIT},
	},
	"idiv": {
		spec{"vb", op{0xF6}, 7, DEFAULT, X64_IMPLICIT},
		spec{"v*", op{0xF7}, 7, AUTO_SIZE, X64_IMPLICIT},
	},
	"inc": {
		spec{"mb", op{0xFE}, 0, LOCK, X64_IMPLICIT},
		spec{"rb", op{0xFE}, 0, DEFAULT, X64_IMPLICIT},
		spec{"m*", op{0xFF}, 0, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"r*", op{0x40}, 0, X86_ONLY | SHORT_ARG, X64_IMPLICIT},
		spec{"r*", op{0xFF}, 0, AUTO_SIZE, X64_IMPLICIT},
	},
	"insb": {
		spec{"", op{0x6C}, X, REP, X64_IMPLICIT},
	},
	"insd": {
		spec{"", op{0x6D}, X, REP, X64_IMPLICIT},
	},
	"insertps": {
		spec{"yomdib", op{0x0F, 0x3A, 0x21}, X, PREF_66, SSE41},
		spec{"yoyoib", op{0x0F, 0x3A, 0x21}, X, PREF_66, SSE41},
	},
	"insertq": {
		spec{"yoyo", op{0x0F, 0x79}, X, PREF_F2, SSE4A | AMD},
		spec{"yoyoibib", op{0x0F, 0x78}, X, PREF_F2, AMD | SSE4A},
	},
	"insw": {
		spec{"", op{0x6D}, X, WORD_SIZE | REP, X64_IMPLICIT},
	},
	"int": {
		spec{"ib", op{0xCD}, X, DEFAULT, X64_IMPLICIT},
	},
	"into": {
		spec{"", op{0xCE}, X, X86_ONLY, X64_IMPLICIT},
	},
	"int01": {
		spec{"", op{0xF1}, X, DEFAULT, X64_IMPLICIT},
	},
	"int03": {
		spec{"", op{0xCC}, X, DEFAULT, X64_IMPLICIT},
	},
	"int1": {
		spec{"", op{0xF1}, X, DEFAULT, X64_IMPLICIT},
	},
	"int3": {
		spec{"", op{0xCC}, X, DEFAULT, X64_IMPLICIT},
	},
	"invd": {
		spec{"", op{0x0F, 0x08}, X, DEFAULT, X64_IMPLICIT},
	},
	"invept": {
		spec{"rqmo", op{0x0F, 0x38, 0x80}, X, PREF_66, VMX},
	},
	"invlpg": {
		spec{"m!", op{0x0F, 0x01}, 7, DEFAULT, X64_IMPLICIT},
	},
	"invlpga": {
		spec{"", op{0x0F, 0x01, 0xDF}, X, DEFAULT, AMD},
		spec{"AqBd", op{0x0F, 0x01, 0xDF}, X, DEFAULT, AMD},
	},
	"invpcid": {
		spec{"rqmo", op{0x0F, 0x38, 0x82}, X, PREF_66, INVPCID},
	},
	"invvpid": {
		spec{"rqmo", op{0x0F, 0x38, 0x81}, X, PREF_66, VMX},
	},
	"iret": {
		spec{"", op{0xCF}, X, DEFAULT, X64_IMPLICIT},
	},
	"iretd": {
		spec{"", op{0xCF}, X, DEFAULT, X64_IMPLICIT},
	},
	"iretq": {
		spec{"", op{0xCF}, X, WITH_REXW, X64_IMPLICIT},
	},
	"iretw": {
		spec{"", op{0xCF}, X, WORD_SIZE, X64_IMPLICIT},
	},
	"jecxz": {
		spec{"ob", op{0xE3}, X, PREF_67, X64_IMPLICIT},
	},
	"jrcxz": {
		spec{"ob", op{0xE3}, X, DEFAULT, X64_IMPLICIT},
	},
	"lahf": {
		spec{"", op{0x9F}, X, DEFAULT, X64_IMPLICIT},
	},
	"lar": {
		spec{"r*mw", op{0x0F, 0x02}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*r*", op{0x0F, 0x02}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"lddqu": {
		spec{"yomo", op{0x0F, 0xF0}, X, PREF_F2, SSE3},
	},
	"ldmxcsr": {
		spec{"md", op{0x0F, 0xAE}, 2, DEFAULT, SSE},
	},
	"lds": {
		spec{"r*m!", op{0xC5}, X, AUTO_SIZE | X86_ONLY, X64_IMPLICIT},
	},
	"lea": {
		spec{"r*m!", op{0x8D}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"leave": {
		spec{"", op{0xC9}, X, DEFAULT, X64_IMPLICIT},
	},
	"les": {
		spec{"r*m!", op{0xC4}, X, AUTO_SIZE | X86_ONLY, X64_IMPLICIT},
	},
	"lfence": {
		spec{"", op{0x0F, 0xAE, 0xE8}, X, DEFAULT, AMD},
	},
	"lfs": {
		spec{"r*m!", op{0x0F, 0xB4}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"lgdt": {
		spec{"m!", op{0x0F, 0x01}, 2, DEFAULT, X64_IMPLICIT},
	},
	"lgs": {
		spec{"r*m!", op{0x0F, 0xB5}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"lidt": {
		spec{"m!", op{0x0F, 0x01}, 3, DEFAULT, X64_IMPLICIT},
	},
	"lldt": {
		spec{"m!", op{0x0F, 0x00}, 2, DEFAULT, X64_IMPLICIT},
		spec{"rw", op{0x0F, 0x00}, 2, DEFAULT, X64_IMPLICIT},
	},
	"llwpcb": {
		spec{"r*", op{0x09, 0x12}, 0, XOP_OP | AUTO_REXW, AMD},
	},
	"lmsw": {
		spec{"m!", op{0x0F, 0x01}, 6, DEFAULT, X64_IMPLICIT},
		spec{"rw", op{0x0F, 0x01}, 6, DEFAULT, X64_IMPLICIT},
	},
	"lodsb": {
		spec{"", op{0xAC}, X, REP, X64_IMPLICIT},
	},
	"lodsd": {
		spec{"", op{0xAD}, X, REP, X64_IMPLICIT},
	},
	"lodsq": {
		spec{"", op{0xAD}, X, WITH_REXW | REP, X64_IMPLICIT},
	},
	"lodsw": {
		spec{"", op{0xAD}, X, WORD_SIZE | REP, X64_IMPLICIT},
	},
	"loop": {
		spec{"ob", op{0xE2}, X, DEFAULT, X64_IMPLICIT},
	},
	"loope": {
		spec{"ob", op{0xE1}, X, DEFAULT, X64_IMPLICIT},
	},
	"loopne": {
		spec{"ob", op{0xE0}, X, DEFAULT, X64_IMPLICIT},
	},
	"loopnz": {
		spec{"ob", op{0xE0}, X, DEFAULT, X64_IMPLICIT},
	},
	"loopz": {
		spec{"ob", op{0xE1}, X, DEFAULT, X64_IMPLICIT},
	},
	"lsl": {
		spec{"r*mw", op{0x0F, 0x03}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*r*", op{0x0F, 0x03}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"lss": {
		spec{"r*m!", op{0x0F, 0xB2}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"ltr": {
		spec{"m!", op{0x0F, 0x00}, 3, DEFAULT, X64_IMPLICIT},
		spec{"rw", op{0x0F, 0x00}, 3, DEFAULT, X64_IMPLICIT},
	},
	"lwpins": {
		spec{"r*v*id", op{0x10, 0x12}, 0, XOP_OP | AUTO_REXW | ENC_VM, AMD},
	},
	"lwpval": {
		spec{"r*v*id", op{0x10, 0x12}, 1, XOP_OP | AUTO_REXW | ENC_VM, AMD},
	},
	"lzcnt": {
		spec{"r*v*", op{0x0F, 0xBD}, X, AUTO_SIZE | PREF_F3, AMD},
	},
	"maskmovdqu": {
		spec{"yoyo", op{0x0F, 0xF7}, X, PREF_66, SSE2},
	},
	"maskmovq": {
		spec{"xqxq", op{0x0F, 0xF7}, X, DEFAULT, MMX},
	},
	"maxpd": {
		spec{"yowo", op{0x0F, 0x5F}, X, PREF_66, SSE2},
	},
	"maxps": {
		spec{"yowo", op{0x0F, 0x5F}, X, DEFAULT, SSE},
	},
	"maxsd": {
		spec{"yomq", op{0x0F, 0x5F}, X, PREF_F2, SSE2},
		spec{"yoyo", op{0x0F, 0x5F}, X, PREF_F2, SSE2},
	},
	"maxss": {
		spec{"yomd", op{0x0F, 0x5F}, X, PREF_F3, SSE},
		spec{"yoyo", op{0x0F, 0x5F}, X, PREF_F3, SSE},
	},
	"mfence": {
		spec{"", op{0x0F, 0xAE, 0xF0}, X, DEFAULT, AMD},
	},
	"minpd": {
		spec{"yowo", op{0x0F, 0x5D}, X, PREF_66, SSE2},
	},
	"minps": {
		spec{"yowo", op{0x0F, 0x5D}, X, DEFAULT, SSE},
	},
	"minsd": {
		spec{"yomq", op{0x0F, 0x5D}, X, PREF_F2, SSE2},
		spec{"yoyo", op{0x0F, 0x5D}, X, PREF_F2, SSE2},
	},
	"minss": {
		spec{"yomd", op{0x0F, 0x5D}, X, PREF_F3, SSE},
		spec{"yoyo", op{0x0F, 0x5D}, X, PREF_F3, SSE},
	},
	"monitor": {
		spec{"", op{0x0F, 0x01, 0xC8}, X, DEFAULT, X64_IMPLICIT},
		spec{"AqBdCd", op{0x0F, 0x01, 0xC8}, X, DEFAULT, X64_IMPLICIT},
	},
	"monitorx": {
		spec{"", op{0x0F, 0x01, 0xFA}, X, DEFAULT, AMD},
		spec{"A*BdCd", op{0x0F, 0x01, 0xFA}, X, DEFAULT, AMD},
	},
	"montmul": {
		spec{"", op{0x0F, 0xA6, 0xC0}, X, PREF_F3, CYRIX},
	},
	"movapd": {
		spec{"moyo", op{0x0F, 0x29}, X, ENC_MR | PREF_66, SSE2},
		spec{"yomo", op{0x0F, 0x28}, X, PREF_66, SSE2},
		spec{"yoyo", op{0x0F, 0x28}, X, PREF_66, SSE2},
		spec{"yoyo", op{0x0F, 0x29}, X, ENC_MR | PREF_66, SSE2},
	},
	"movaps": {
		spec{"yowo", op{0x0F, 0x28}, X, DEFAULT, SSE},
		spec{"woyo", op{0x0F, 0x29}, X, ENC_MR, SSE},
	},
	"movbe": {
		spec{"m*r*", op{0x0F, 0x38, 0xF1}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
		spec{"r*m*", op{0x0F, 0x38, 0xF0}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"movd": {
		spec{"mdyo", op{0x0F, 0x7E}, X, ENC_MR | PREF_66, SSE2},
		spec{"xqvd", op{0x0F, 0x6E}, X, DEFAULT, MMX},
		spec{"xqvq", op{0x0F, 0x6E}, X, WITH_REXW, MMX},
		spec{"yomd", op{0x0F, 0x6E}, X, PREF_66, SSE2},
		spec{"yovd", op{0x0F, 0x6E}, X, PREF_66, SSE2},
		spec{"vdxq", op{0x0F, 0x7E}, X, ENC_MR, MMX},
		spec{"vdyo", op{0x0F, 0x7E}, X, ENC_MR | PREF_66, SSE2},
		spec{"vqxq", op{0x0F, 0x7E}, X, WITH_REXW | ENC_MR, MMX},
	},
	"movddup": {
		spec{"yomq", op{0x0F, 0x12}, X, PREF_F2, SSE3},
		spec{"yoyo", op{0x0F, 0x12}, X, PREF_F2, SSE3},
	},
	"movdq2q": {
		spec{"xqyo", op{0x0F, 0xD6}, X, PREF_F2, SSE2},
	},
	"movdqa": {
		spec{"moyo", op{0x0F, 0x7F}, X, ENC_MR | PREF_66, SSE2},
		spec{"yomo", op{0x0F, 0x6F}, X, PREF_66, SSE2},
		spec{"yoyo", op{0x0F, 0x6F}, X, PREF_66, SSE2},
		spec{"yoyo", op{0x0F, 0x7F}, X, ENC_MR | PREF_66, SSE2},
	},
	"movdqu": {
		spec{"moyo", op{0x0F, 0x7F}, X, ENC_MR | PREF_F3, SSE2},
		spec{"yomo", op{0x0F, 0x6F}, X, PREF_F3, SSE2},
		spec{"yoyo", op{0x0F, 0x6F}, X, PREF_F3, SSE2},
		spec{"yoyo", op{0x0F, 0x7F}, X, ENC_MR | PREF_F3, SSE2},
	},
	"movhlps": {
		spec{"yoyo", op{0x0F, 0x12}, X, DEFAULT, SSE},
	},
	"movhpd": {
		spec{"m!yo", op{0x0F, 0x17}, X, ENC_MR | PREF_66, SSE2},
		spec{"yom!", op{0x0F, 0x16}, X, PREF_66, SSE2},
	},
	"movhps": {
		spec{"mqyo", op{0x0F, 0x17}, X, ENC_MR, SSE},
		spec{"yomq", op{0x0F, 0x16}, X, DEFAULT, SSE},
	},
	"movlhps": {
		spec{"yoyo", op{0x0F, 0x16}, X, DEFAULT, SSE},
	},
	"movlpd": {
		spec{"mqyo", op{0x0F, 0x13}, X, ENC_MR | PREF_66, SSE2},
		spec{"yomq", op{0x0F, 0x12}, X, PREF_66, SSE2},
	},
	"movlps": {
		spec{"mqyo", op{0x0F, 0x13}, X, ENC_MR, SSE},
		spec{"yomq", op{0x0F, 0x12}, X, DEFAULT, SSE},
	},
	"movmskpd": {
		spec{"rdyo", op{0x0F, 0x50}, X, PREF_66, SSE2},
		spec{"rqyo", op{0x0F, 0x50}, X, WITH_REXW | PREF_66, SSE2},
	},
	"movmskps": {
		spec{"rdyo", op{0x0F, 0x50}, X, DEFAULT, SSE},
		spec{"rqyo", op{0x0F, 0x50}, X, WITH_REXW, SSE},
	},
	"movntdq": {
		spec{"moyo", op{0x0F, 0xE7}, X, ENC_MR | PREF_66, SSE2},
	},
	"movntdqa": {
		spec{"yomo", op{0x0F, 0x38, 0x2A}, X, PREF_66, SSE41},
	},
	"movnti": {
		spec{"mdrd", op{0x0F, 0xC3}, X, ENC_MR, X64_IMPLICIT},
		spec{"mqrq", op{0x0F, 0xC3}, X, WITH_REXW | ENC_MR, X64_IMPLICIT},
	},
	"movntpd": {
		spec{"moyo", op{0x0F, 0x2B}, X, ENC_MR | PREF_66, SSE2},
	},
	"movntps": {
		spec{"moyo", op{0x0F, 0x2B}, X, ENC_MR, SSE},
	},
	"movntq": {
		spec{"mqxq", op{0x0F, 0xE7}, X, ENC_MR, MMX},
	},
	"movntsd": {
		spec{"mqyo", op{0x0F, 0x2B}, X, ENC_MR | PREF_F2, AMD | SSE4A},
	},
	"movntss": {
		spec{"mdyo", op{0x0F, 0x2B}, X, ENC_MR | PREF_F3, SSE4A | AMD},
	},
	"movq": {
		spec{"mqyo", op{0x0F, 0xD6}, X, ENC_MR | PREF_66, SSE2},
		spec{"xquq", op{0x0F, 0x6F}, X, DEFAULT, MMX},
		spec{"xqvq", op{0x0F, 0x6E}, X, WITH_REXW, MMX},
		spec{"yomq", op{0x0F, 0x7E}, X, PREF_F3, SSE2},
		spec{"yovq", op{0x0F, 0x6E}, X, WITH_REXW | PREF_66, SSE2},
		spec{"yoyo", op{0x0F, 0x7E}, X, PREF_F3, SSE2},
		spec{"yoyo", op{0x0F, 0xD6}, X, ENC_MR | PREF_66, SSE2},
		spec{"uqxq", op{0x0F, 0x7F}, X, ENC_MR, MMX},
		spec{"vqxq", op{0x0F, 0x7E}, X, WITH_REXW | ENC_MR, MMX},
		spec{"vqyo", op{0x0F, 0x7E}, X, WITH_REXW | ENC_MR | PREF_66, SSE2},
	},
	"movq2dq": {
		spec{"yoxq", op{0x0F, 0xD6}, X, PREF_F3, SSE2},
	},
	"movsb": {
		spec{"", op{0xA4}, X, REP, X64_IMPLICIT},
	},
	"movsd": {
		spec{"", op{0xA5}, X, REP, X64_IMPLICIT},
		spec{"mqyo", op{0x0F, 0x11}, X, ENC_MR | PREF_F2, SSE2},
		spec{"yomq", op{0x0F, 0x10}, X, PREF_F2, SSE2},
		spec{"yoyo", op{0x0F, 0x10}, X, PREF_F2, SSE2},
		spec{"yoyo", op{0x0F, 0x11}, X, ENC_MR | PREF_F2, SSE2},
	},
	"movshdup": {
		spec{"yomq", op{0x0F, 0x16}, X, PREF_F3, SSE3},
		spec{"yoyo", op{0x0F, 0x16}, X, PREF_F3, SSE3},
	},
	"movsldup": {
		spec{"yomq", op{0x0F, 0x12}, X, PREF_F3, SSE3},
		spec{"yoyo", op{0x0F, 0x12}, X, PREF_F3, SSE3},
	},
	"movsq": {
		spec{"", op{0xA5}, X, WITH_REXW | REP, X64_IMPLICIT},
	},
	"movss": {
		spec{"mdyo", op{0x0F, 0x11}, X, ENC_MR | PREF_F3, SSE},
		spec{"yomd", op{0x0F, 0x10}, X, PREF_F3, SSE},
		spec{"yoyo", op{0x0F, 0x10}, X, PREF_F3, SSE},
	},
	"movsw": {
		spec{"", op{0xA5}, X, WORD_SIZE | REP, X64_IMPLICIT},
	},
	"movsx": {
		spec{"rqvd", op{0x63}, X, WITH_REXW, X64_IMPLICIT},
		spec{"rwmb", op{0x0F, 0xBE}, X, WORD_SIZE, X64_IMPLICIT},
		spec{"r*vb", op{0x0F, 0xBE}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*vw", op{0x0F, 0xBF}, X, AUTO_REXW | EXACT_SIZE, X64_IMPLICIT},
	},
	"movsxd": {
		spec{"rqvd", op{0x63}, X, WITH_REXW, X64_IMPLICIT},
	},
	"movupd": {
		spec{"moyo", op{0x0F, 0x11}, X, ENC_MR | PREF_66, SSE2},
		spec{"yomo", op{0x0F, 0x10}, X, PREF_66, SSE2},
		spec{"yoyo", op{0x0F, 0x10}, X, PREF_66, SSE2},
		spec{"yoyo", op{0x0F, 0x11}, X, ENC_MR | PREF_66, SSE2},
	},
	"movups": {
		spec{"yowo", op{0x0F, 0x10}, X, DEFAULT, SSE},
		spec{"woyo", op{0x0F, 0x11}, X, ENC_MR, SSE},
	},
	"movzx": {
		spec{"rwmb", op{0x0F, 0xB6}, X, WORD_SIZE, X64_IMPLICIT},
		spec{"r*vb", op{0x0F, 0xB6}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*vw", op{0x0F, 0xB7}, X, AUTO_REXW | EXACT_SIZE, X64_IMPLICIT},
	},
	"mpsadbw": {
		spec{"yomqib", op{0x0F, 0x3A, 0x42}, X, PREF_66, SSE41},
		spec{"yoyoib", op{0x0F, 0x3A, 0x42}, X, PREF_66, SSE41},
	},
	"mul": {
		spec{"vb", op{0xF6}, 4, DEFAULT, X64_IMPLICIT},
		spec{"v*", op{0xF7}, 4, AUTO_SIZE, X64_IMPLICIT},
	},
	"mulpd": {
		spec{"yowo", op{0x0F, 0x59}, X, PREF_66, SSE2},
	},
	"mulps": {
		spec{"yowo", op{0x0F, 0x59}, X, DEFAULT, SSE},
	},
	"mulsd": {
		spec{"yomq", op{0x0F, 0x59}, X, PREF_F2, SSE2},
		spec{"yoyo", op{0x0F, 0x59}, X, PREF_F2, SSE2},
	},
	"mulss": {
		spec{"yomd", op{0x0F, 0x59}, X, PREF_F3, SSE},
		spec{"yoyo", op{0x0F, 0x59}, X, PREF_F3, SSE},
	},
	"mulx": {
		spec{"r*r*v*", op{0x02, 0xF6}, X, VEX_OP | AUTO_REXW | PREF_F2, BMI2},
	},
	"mwait": {
		spec{"", op{0x0F, 0x01, 0xC9}, X, DEFAULT, X64_IMPLICIT},
		spec{"AdBd", op{0x0F, 0x01, 0xC9}, X, DEFAULT, X64_IMPLICIT},
	},
	"mwaitx": {
		spec{"", op{0x0F, 0x01, 0xFB}, X, DEFAULT, AMD},
		spec{"AdBd", op{0x0F, 0x01, 0xFB}, X, DEFAULT, AMD},
	},
	"neg": {
		spec{"mb", op{0xF6}, 3, LOCK, X64_IMPLICIT},
		spec{"rb", op{0xF6}, 3, DEFAULT, X64_IMPLICIT},
		spec{"m*", op{0xF7}, 3, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"r*", op{0xF7}, 3, AUTO_SIZE, X64_IMPLICIT},
	},
	"nop": {
		spec{"", op{0x90}, X, DEFAULT, X64_IMPLICIT},
		spec{"v*", op{0x0F, 0x1F}, 0, AUTO_SIZE, X64_IMPLICIT},
	},
	"not": {
		spec{"mb", op{0xF6}, 2, LOCK, X64_IMPLICIT},
		spec{"rb", op{0xF6}, 2, DEFAULT, X64_IMPLICIT},
		spec{"m*", op{0xF7}, 2, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"r*", op{0xF7}, 2, AUTO_SIZE, X64_IMPLICIT},
	},
	"or": {
		spec{"Abib", op{0x0C}, X, DEFAULT, X64_IMPLICIT},
		spec{"mbib", op{0x80}, 1, LOCK, X64_IMPLICIT},
		spec{"mbrb", op{0x08}, X, LOCK | ENC_MR, X64_IMPLICIT},
		spec{"rbib", op{0x80}, 1, DEFAULT, X64_IMPLICIT},
		spec{"rbrb", op{0x08}, X, ENC_MR, X64_IMPLICIT},
		spec{"rbvb", op{0x0A}, X, DEFAULT, X64_IMPLICIT},
		spec{"r*ib", op{0x83}, 1, AUTO_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"A*i*", op{0x0D}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"m*i*", op{0x81}, 1, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*ib", op{0x83}, 1, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*r*", op{0x09}, X, AUTO_SIZE | LOCK | ENC_MR, X64_IMPLICIT},
		spec{"r*i*", op{0x81}, 1, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*r*", op{0x09}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
		spec{"r*v*", op{0x0B}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"orpd": {
		spec{"yowo", op{0x0F, 0x56}, X, PREF_66, SSE2},
	},
	"orps": {
		spec{"yowo", op{0x0F, 0x56}, X, DEFAULT, SSE},
	},
	"outsb": {
		spec{"", op{0x6E}, X, REP, X64_IMPLICIT},
	},
	"outsd": {
		spec{"", op{0x6F}, X, REP, X64_IMPLICIT},
	},
	"outsw": {
		spec{"", op{0x6F}, X, WORD_SIZE | REP, X64_IMPLICIT},
	},
	"pabsb": {
		spec{"xquq", op{0x0F, 0x38, 0x1C}, X, DEFAULT, MMX | SSSE3},
		spec{"yomq", op{0x0F, 0x38, 0x1C}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x1C}, X, PREF_66, SSSE3},
	},
	"pabsd": {
		spec{"xquq", op{0x0F, 0x38, 0x1E}, X, DEFAULT, MMX | SSSE3},
		spec{"yomq", op{0x0F, 0x38, 0x1E}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x1E}, X, PREF_66, SSSE3},
	},
	"pabsw": {
		spec{"xquq", op{0x0F, 0x38, 0x1D}, X, DEFAULT, SSSE3 | MMX},
		spec{"yomq", op{0x0F, 0x38, 0x1D}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x1D}, X, PREF_66, SSSE3},
	},
	"packssdw": {
		spec{"xquq", op{0x0F, 0x6B}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x6B}, X, PREF_66, SSE2},
	},
	"packsswb": {
		spec{"xquq", op{0x0F, 0x63}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x63}, X, PREF_66, SSE2},
	},
	"packusdw": {
		spec{"yomq", op{0x0F, 0x38, 0x2B}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x2B}, X, PREF_66, SSE41},
	},
	"packuswb": {
		spec{"xquq", op{0x0F, 0x67}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x67}, X, PREF_66, SSE2},
	},
	"paddb": {
		spec{"xquq", op{0x0F, 0xFC}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xFC}, X, PREF_66, SSE2},
	},
	"paddd": {
		spec{"xquq", op{0x0F, 0xFE}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xFE}, X, PREF_66, SSE2},
	},
	"paddq": {
		spec{"xquq", op{0x0F, 0xD4}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xD4}, X, PREF_66, SSE2},
	},
	"paddsb": {
		spec{"xquq", op{0x0F, 0xEC}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xEC}, X, PREF_66, SSE2},
	},
	"paddsiw": {
		spec{"xquq", op{0x0F, 0x51}, X, DEFAULT, MMX | CYRIX},
	},
	"paddsw": {
		spec{"xquq", op{0x0F, 0xED}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xED}, X, PREF_66, SSE2},
	},
	"paddusb": {
		spec{"xquq", op{0x0F, 0xDC}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xDC}, X, PREF_66, SSE2},
	},
	"paddusw": {
		spec{"xquq", op{0x0F, 0xDD}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xDD}, X, PREF_66, SSE2},
	},
	"paddw": {
		spec{"xquq", op{0x0F, 0xFD}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xFD}, X, PREF_66, SSE2},
	},
	"palignr": {
		spec{"xquqib", op{0x0F, 0x3A, 0x0F}, X, DEFAULT, SSSE3 | MMX},
		spec{"yomqib", op{0x0F, 0x3A, 0x0F}, X, PREF_66, SSSE3},
		spec{"yoyoib", op{0x0F, 0x3A, 0x0F}, X, PREF_66, SSSE3},
	},
	"pand": {
		spec{"xquq", op{0x0F, 0xDB}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xDB}, X, PREF_66, SSE2},
	},
	"pandn": {
		spec{"xquq", op{0x0F, 0xDF}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xDF}, X, PREF_66, SSE2},
	},
	"pause": {
		spec{"", op{0x90}, X, PREF_F3, X64_IMPLICIT},
	},
	"paveb": {
		spec{"xquq", op{0x0F, 0x50}, X, DEFAULT, MMX | CYRIX},
	},
	"pavgb": {
		spec{"xquq", op{0x0F, 0xE0}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xE0}, X, PREF_66, SSE2},
	},
	"pavgusb": {
		spec{"xquq", op{0x0F, 0x0F, 0xBF}, X, IMM_OP, TDNOW},
	},
	"pavgw": {
		spec{"xquq", op{0x0F, 0xE3}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xE3}, X, PREF_66, SSE2},
	},
	"pblendvb": {
		spec{"yomq", op{0x0F, 0x38, 0x10}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x10}, X, PREF_66, SSE41},
	},
	"pblendw": {
		spec{"yomqib", op{0x0F, 0x3A, 0x0E}, X, PREF_66, SSE41},
		spec{"yoyoib", op{0x0F, 0x3A, 0x0E}, X, PREF_66, SSE41},
	},
	"pclmulhqhqdq": {
		spec{"yowo", op{0x0F, 0x3A, 0x44, 0x11}, X, IMM_OP | PREF_66, SSE},
	},
	"pclmulhqlqdq": {
		spec{"yowo", op{0x0F, 0x3A, 0x44, 0x01}, X, PREF_66 | IMM_OP, SSE},
	},
	"pclmullqhqdq": {
		spec{"yowo", op{0x0F, 0x3A, 0x44, 0x10}, X, PREF_66 | IMM_OP, SSE},
	},
	"pclmullqlqdq": {
		spec{"yowo", op{0x0F, 0x3A, 0x44, 0x00}, X, PREF_66 | IMM_OP, SSE},
	},
	"pclmulqdq": {
		spec{"yowoib", op{0x0F, 0x3A, 0x44}, X, PREF_66, SSE},
	},
	"pcmpeqb": {
		spec{"xquq", op{0x0F, 0x74}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x74}, X, PREF_66, SSE2},
	},
	"pcmpeqd": {
		spec{"xquq", op{0x0F, 0x76}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x76}, X, PREF_66, SSE2},
	},
	"pcmpeqq": {
		spec{"yomq", op{0x0F, 0x38, 0x29}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x29}, X, PREF_66, SSE41},
	},
	"pcmpeqw": {
		spec{"xquq", op{0x0F, 0x75}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x75}, X, PREF_66, SSE2},
	},
	"pcmpestri": {
		spec{"yomqib", op{0x0F, 0x3A, 0x61}, X, PREF_66, SSE42},
		spec{"yoyoib", op{0x0F, 0x3A, 0x61}, X, PREF_66, SSE42},
	},
	"pcmpestrm": {
		spec{"yomqib", op{0x0F, 0x3A, 0x60}, X, PREF_66, SSE42},
		spec{"yoyoib", op{0x0F, 0x3A, 0x60}, X, PREF_66, SSE42},
	},
	"pcmpgtb": {
		spec{"xquq", op{0x0F, 0x64}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x64}, X, PREF_66, SSE2},
	},
	"pcmpgtd": {
		spec{"xquq", op{0x0F, 0x66}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x66}, X, PREF_66, SSE2},
	},
	"pcmpgtq": {
		spec{"yomq", op{0x0F, 0x38, 0x37}, X, PREF_66, SSE42},
		spec{"yoyo", op{0x0F, 0x38, 0x37}, X, PREF_66, SSE42},
	},
	"pcmpgtw": {
		spec{"xquq", op{0x0F, 0x65}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x65}, X, PREF_66, SSE2},
	},
	"pcmpistri": {
		spec{"yomqib", op{0x0F, 0x3A, 0x63}, X, PREF_66, SSE42},
		spec{"yoyoib", op{0x0F, 0x3A, 0x63}, X, PREF_66, SSE42},
	},
	"pcmpistrm": {
		spec{"yomqib", op{0x0F, 0x3A, 0x62}, X, PREF_66, SSE42},
		spec{"yoyoib", op{0x0F, 0x3A, 0x62}, X, PREF_66, SSE42},
	},
	"pdep": {
		spec{"r*r*v*", op{0x02, 0xF5}, X, VEX_OP | AUTO_REXW | PREF_F2, BMI2},
	},
	"pdistib": {
		spec{"xqmq", op{0x0F, 0x54}, X, DEFAULT, MMX | CYRIX},
	},
	"pext": {
		spec{"r*r*v*", op{0x02, 0xF5}, X, VEX_OP | AUTO_REXW | PREF_F3, BMI2},
	},
	"pextrb": {
		spec{"mbyoib", op{0x0F, 0x3A, 0x14}, X, ENC_MR | PREF_66, SSE41},
		spec{"rdyoib", op{0x0F, 0x3A, 0x14}, X, ENC_MR | PREF_66, SSE41},
		spec{"rqyoib", op{0x0F, 0x3A, 0x14}, X, WITH_REXW | ENC_MR | PREF_66, SSE41},
	},
	"pextrd": {
		spec{"vdyoib", op{0x0F, 0x3A, 0x16}, X, ENC_MR | PREF_66, SSE41},
	},
	"pextrq": {
		spec{"vqyoib", op{0x0F, 0x3A, 0x16}, X, WITH_REXW | ENC_MR | PREF_66, SSE41},
	},
	"pextrw": {
		spec{"mwyoib", op{0x0F, 0x3A, 0x15}, X, ENC_MR | PREF_66, SSE41},
		spec{"rdxqib", op{0x0F, 0xC5}, X, DEFAULT, MMX},
		spec{"rdyoib", op{0x0F, 0xC5}, X, PREF_66, SSE2},
		spec{"rdyoib", op{0x0F, 0x3A, 0x15}, X, ENC_MR | PREF_66, SSE41},
		spec{"rqyoib", op{0x0F, 0x3A, 0x15}, X, WITH_REXW | ENC_MR | PREF_66, SSE41},
	},
	"pf2id": {
		spec{"xquq", op{0x0F, 0x0F, 0x1D}, X, IMM_OP, TDNOW},
	},
	"pf2iw": {
		spec{"xquq", op{0x0F, 0x0F, 0x1C}, X, IMM_OP, TDNOW},
	},
	"pfacc": {
		spec{"xquq", op{0x0F, 0x0F, 0xAE}, X, IMM_OP, TDNOW},
	},
	"pfadd": {
		spec{"xquq", op{0x0F, 0x0F, 0x9E}, X, IMM_OP, TDNOW},
	},
	"pfcmpeq": {
		spec{"xquq", op{0x0F, 0x0F, 0xB0}, X, IMM_OP, TDNOW},
	},
	"pfcmpge": {
		spec{"xquq", op{0x0F, 0x0F, 0x90}, X, IMM_OP, TDNOW},
	},
	"pfcmpgt": {
		spec{"xquq", op{0x0F, 0x0F, 0xA0}, X, IMM_OP, TDNOW},
	},
	"pfmax": {
		spec{"xquq", op{0x0F, 0x0F, 0xA4}, X, IMM_OP, TDNOW},
	},
	"pfmin": {
		spec{"xquq", op{0x0F, 0x0F, 0x94}, X, IMM_OP, TDNOW},
	},
	"pfmul": {
		spec{"xquq", op{0x0F, 0x0F, 0xB4}, X, IMM_OP, TDNOW},
	},
	"pfnacc": {
		spec{"xquq", op{0x0F, 0x0F, 0x8A}, X, IMM_OP, TDNOW},
	},
	"pfpnacc": {
		spec{"xquq", op{0x0F, 0x0F, 0x8E}, X, IMM_OP, TDNOW},
	},
	"pfrcp": {
		spec{"xquq", op{0x0F, 0x0F, 0x96}, X, IMM_OP, TDNOW},
	},
	"pfrcpit1": {
		spec{"xquq", op{0x0F, 0x0F, 0xA6}, X, IMM_OP, TDNOW},
	},
	"pfrcpit2": {
		spec{"xquq", op{0x0F, 0x0F, 0xB6}, X, IMM_OP, TDNOW},
	},
	"pfrcpv": {
		spec{"xquq", op{0x0F, 0x0F, 0x86}, X, IMM_OP, TDNOW | CYRIX},
	},
	"pfrsqit1": {
		spec{"xquq", op{0x0F, 0x0F, 0xA7}, X, IMM_OP, TDNOW},
	},
	"pfrsqrt": {
		spec{"xquq", op{0x0F, 0x0F, 0x97}, X, IMM_OP, TDNOW},
	},
	"pfrsqrtv": {
		spec{"xquq", op{0x0F, 0x0F, 0x87}, X, IMM_OP, CYRIX | TDNOW},
	},
	"pfsub": {
		spec{"xquq", op{0x0F, 0x0F, 0x9A}, X, IMM_OP, TDNOW},
	},
	"pfsubr": {
		spec{"xquq", op{0x0F, 0x0F, 0xAA}, X, IMM_OP, TDNOW},
	},
	"phaddd": {
		spec{"xquq", op{0x0F, 0x38, 0x02}, X, DEFAULT, MMX | SSSE3},
		spec{"yomq", op{0x0F, 0x38, 0x02}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x02}, X, PREF_66, SSSE3},
	},
	"phaddsw": {
		spec{"xquq", op{0x0F, 0x38, 0x03}, X, DEFAULT, MMX | SSSE3},
		spec{"yomq", op{0x0F, 0x38, 0x03}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x03}, X, PREF_66, SSSE3},
	},
	"phaddw": {
		spec{"xquq", op{0x0F, 0x38, 0x01}, X, DEFAULT, MMX | SSSE3},
		spec{"yomq", op{0x0F, 0x38, 0x01}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x01}, X, PREF_66, SSSE3},
	},
	"phminposuw": {
		spec{"yomq", op{0x0F, 0x38, 0x41}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x41}, X, PREF_66, SSE41},
	},
	"phsubd": {
		spec{"xquq", op{0x0F, 0x38, 0x06}, X, DEFAULT, SSSE3 | MMX},
		spec{"yomq", op{0x0F, 0x38, 0x06}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x06}, X, PREF_66, SSSE3},
	},
	"phsubsw": {
		spec{"xquq", op{0x0F, 0x38, 0x07}, X, DEFAULT, SSSE3 | MMX},
		spec{"yomq", op{0x0F, 0x38, 0x07}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x07}, X, PREF_66, SSSE3},
	},
	"phsubw": {
		spec{"xquq", op{0x0F, 0x38, 0x05}, X, DEFAULT, SSSE3 | MMX},
		spec{"yomq", op{0x0F, 0x38, 0x05}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x05}, X, PREF_66, SSSE3},
	},
	"pi2fd": {
		spec{"xquq", op{0x0F, 0x0F, 0x0D}, X, IMM_OP, TDNOW},
	},
	"pi2fw": {
		spec{"xquq", op{0x0F, 0x0F, 0x0C}, X, IMM_OP, TDNOW},
	},
	"pinsrb": {
		spec{"yom!ib", op{0x0F, 0x3A, 0x20}, X, PREF_66, SSE41},
		spec{"yordib", op{0x0F, 0x3A, 0x20}, X, PREF_66, SSE41},
		spec{"yovbib", op{0x0F, 0x3A, 0x20}, X, PREF_66, SSE41},
	},
	"pinsrd": {
		spec{"yom!ib", op{0x0F, 0x3A, 0x22}, X, PREF_66, SSE41},
		spec{"yovdib", op{0x0F, 0x3A, 0x22}, X, PREF_66, SSE41},
	},
	"pinsrq": {
		spec{"yom!ib", op{0x0F, 0x3A, 0x22}, X, WITH_REXW | PREF_66, SSE41},
		spec{"yovqib", op{0x0F, 0x3A, 0x22}, X, WITH_REXW | PREF_66, SSE41},
	},
	"pinsrw": {
		spec{"xqm!ib", op{0x0F, 0xC4}, X, DEFAULT, MMX},
		spec{"xqrdib", op{0x0F, 0xC4}, X, DEFAULT, MMX},
		spec{"xqvwib", op{0x0F, 0xC4}, X, DEFAULT, MMX},
		spec{"yom!ib", op{0x0F, 0xC4}, X, PREF_66, SSE2},
		spec{"yomwib", op{0x0F, 0xC4}, X, PREF_66, SSE2},
		spec{"yordib", op{0x0F, 0xC4}, X, PREF_66, SSE2},
		spec{"yorwib", op{0x0F, 0xC4}, X, PREF_66, SSE2},
	},
	"pmachriw": {
		spec{"xqmq", op{0x0F, 0x5E}, X, DEFAULT, MMX | CYRIX},
	},
	"pmaddubsw": {
		spec{"xquq", op{0x0F, 0x38, 0x04}, X, DEFAULT, MMX | SSSE3},
		spec{"yomq", op{0x0F, 0x38, 0x04}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x04}, X, PREF_66, SSSE3},
	},
	"pmaddwd": {
		spec{"xquq", op{0x0F, 0xF5}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xF5}, X, PREF_66, SSE2},
	},
	"pmagw": {
		spec{"xquq", op{0x0F, 0x52}, X, DEFAULT, CYRIX | MMX},
	},
	"pmaxsb": {
		spec{"yomq", op{0x0F, 0x38, 0x3C}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x3C}, X, PREF_66, SSE41},
	},
	"pmaxsd": {
		spec{"yomq", op{0x0F, 0x38, 0x3D}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x3D}, X, PREF_66, SSE41},
	},
	"pmaxsw": {
		spec{"xquq", op{0x0F, 0xEE}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xEE}, X, PREF_66, SSE2},
	},
	"pmaxub": {
		spec{"xquq", op{0x0F, 0xDE}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xDE}, X, PREF_66, SSE2},
	},
	"pmaxud": {
		spec{"yomq", op{0x0F, 0x38, 0x3F}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x3F}, X, PREF_66, SSE41},
	},
	"pmaxuw": {
		spec{"yomq", op{0x0F, 0x38, 0x3E}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x3E}, X, PREF_66, SSE41},
	},
	"pminsb": {
		spec{"yomq", op{0x0F, 0x38, 0x38}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x38}, X, PREF_66, SSE41},
	},
	"pminsd": {
		spec{"yomq", op{0x0F, 0x38, 0x39}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x39}, X, PREF_66, SSE41},
	},
	"pminsw": {
		spec{"xquq", op{0x0F, 0xEA}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xEA}, X, PREF_66, SSE2},
	},
	"pminub": {
		spec{"xquq", op{0x0F, 0xDA}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xDA}, X, PREF_66, SSE2},
	},
	"pminud": {
		spec{"yomq", op{0x0F, 0x38, 0x3B}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x3B}, X, PREF_66, SSE41},
	},
	"pminuw": {
		spec{"yomq", op{0x0F, 0x38, 0x3A}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x3A}, X, PREF_66, SSE41},
	},
	"pmovmskb": {
		spec{"rdxq", op{0x0F, 0xD7}, X, DEFAULT, MMX},
		spec{"rdyo", op{0x0F, 0xD7}, X, PREF_66, SSE2},
	},
	"pmovsxbd": {
		spec{"yomd", op{0x0F, 0x38, 0x21}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x21}, X, PREF_66, SSE41},
	},
	"pmovsxbq": {
		spec{"yomw", op{0x0F, 0x38, 0x22}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x22}, X, PREF_66, SSE41},
	},
	"pmovsxbw": {
		spec{"yomq", op{0x0F, 0x38, 0x20}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x20}, X, PREF_66, SSE41},
	},
	"pmovsxdq": {
		spec{"yomq", op{0x0F, 0x38, 0x25}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x25}, X, PREF_66, SSE41},
	},
	"pmovsxwd": {
		spec{"yomq", op{0x0F, 0x38, 0x23}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x23}, X, PREF_66, SSE41},
	},
	"pmovsxwq": {
		spec{"yomd", op{0x0F, 0x38, 0x24}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x24}, X, PREF_66, SSE41},
	},
	"pmovzxbd": {
		spec{"yomd", op{0x0F, 0x38, 0x31}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x31}, X, PREF_66, SSE41},
	},
	"pmovzxbq": {
		spec{"yomw", op{0x0F, 0x38, 0x32}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x32}, X, PREF_66, SSE41},
	},
	"pmovzxbw": {
		spec{"yomq", op{0x0F, 0x38, 0x30}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x30}, X, PREF_66, SSE41},
	},
	"pmovzxdq": {
		spec{"yomq", op{0x0F, 0x38, 0x35}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x35}, X, PREF_66, SSE41},
	},
	"pmovzxwd": {
		spec{"yomq", op{0x0F, 0x38, 0x33}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x33}, X, PREF_66, SSE41},
	},
	"pmovzxwq": {
		spec{"yomd", op{0x0F, 0x38, 0x34}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x34}, X, PREF_66, SSE41},
	},
	"pmuldq": {
		spec{"yomq", op{0x0F, 0x38, 0x28}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x28}, X, PREF_66, SSE41},
	},
	"pmulhriw": {
		spec{"xquq", op{0x0F, 0x5D}, X, DEFAULT, CYRIX | MMX},
	},
	"pmulhrsw": {
		spec{"xquq", op{0x0F, 0x38, 0x0B}, X, DEFAULT, MMX | SSSE3},
		spec{"yomq", op{0x0F, 0x38, 0x0B}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x0B}, X, PREF_66, SSSE3},
	},
	"pmulhrwa": {
		spec{"xquq", op{0x0F, 0x0F, 0xB7}, X, IMM_OP, TDNOW},
	},
	"pmulhrwc": {
		spec{"xquq", op{0x0F, 0x59}, X, DEFAULT, MMX | CYRIX},
	},
	"pmulhuw": {
		spec{"xquq", op{0x0F, 0xE4}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xE4}, X, PREF_66, SSE2},
	},
	"pmulhw": {
		spec{"xquq", op{0x0F, 0xE5}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xE5}, X, PREF_66, SSE2},
	},
	"pmulld": {
		spec{"yomq", op{0x0F, 0x38, 0x40}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x40}, X, PREF_66, SSE41},
	},
	"pmullw": {
		spec{"xquq", op{0x0F, 0xD5}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xD5}, X, PREF_66, SSE2},
	},
	"pmuludq": {
		spec{"xquq", op{0x0F, 0xF4}, X, DEFAULT, SSE2},
		spec{"yowo", op{0x0F, 0xF4}, X, PREF_66, SSE2},
	},
	"pmvgezb": {
		spec{"xqmq", op{0x0F, 0x5C}, X, DEFAULT, CYRIX | MMX},
	},
	"pmvlzb": {
		spec{"xqmq", op{0x0F, 0x5B}, X, DEFAULT, CYRIX | MMX},
	},
	"pmvnzb": {
		spec{"xqmq", op{0x0F, 0x5A}, X, DEFAULT, CYRIX | MMX},
	},
	"pmvzb": {
		spec{"xqmq", op{0x0F, 0x58}, X, DEFAULT, MMX | CYRIX},
	},
	"pop": {
		spec{"Qw", op{0x07}, X, X86_ONLY, X64_IMPLICIT},
		spec{"Sw", op{0x17}, X, X86_ONLY, X64_IMPLICIT},
		spec{"Tw", op{0x1F}, X, X86_ONLY, X64_IMPLICIT},
		spec{"Uw", op{0x0F, 0xA1}, X, DEFAULT, X64_IMPLICIT},
		spec{"Vw", op{0x0F, 0xA9}, X, DEFAULT, X64_IMPLICIT},
		spec{"r*", op{0x58}, X, AUTO_NO32 | SHORT_ARG, X64_IMPLICIT},
		spec{"v*", op{0x8F}, 0, AUTO_NO32, X64_IMPLICIT},
	},
	"popa": {
		spec{"", op{0x61}, X, X86_ONLY | WORD_SIZE, X64_IMPLICIT},
	},
	"popad": {
		spec{"", op{0x61}, X, X86_ONLY, X64_IMPLICIT},
	},
	"popcnt": {
		spec{"r*v*", op{0x0F, 0xB8}, X, AUTO_SIZE | PREF_F3, X64_IMPLICIT},
	},
	"popf": {
		spec{"", op{0x9D}, X, DEFAULT, X64_IMPLICIT},
	},
	"popfq": {
		spec{"", op{0x9D}, X, DEFAULT, X64_IMPLICIT},
	},
	"popfw": {
		spec{"", op{0x9D}, X, WORD_SIZE, X64_IMPLICIT},
	},
	"por": {
		spec{"xquq", op{0x0F, 0xEB}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xEB}, X, PREF_66, SSE2},
	},
	"prefetch": {
		spec{"mq", op{0x0F, 0x0D}, 0, DEFAULT, TDNOW},
	},
	"prefetchnta": {
		spec{"mb", op{0x0F, 0x18}, 0, DEFAULT, X64_IMPLICIT},
	},
	"prefetcht0": {
		spec{"mb", op{0x0F, 0x18}, 1, DEFAULT, X64_IMPLICIT},
	},
	"prefetcht1": {
		spec{"mb", op{0x0F, 0x18}, 2, DEFAULT, X64_IMPLICIT},
	},
	"prefetcht2": {
		spec{"mb", op{0x0F, 0x18}, 3, DEFAULT, X64_IMPLICIT},
	},
	"prefetchw": {
		spec{"mq", op{0x0F, 0x0D}, 1, DEFAULT, TDNOW},
	},
	"prefetchwt1": {
		spec{"mb", op{0x0F, 0x0D}, 2, DEFAULT, PREFETCHWT1},
	},
	"psadbw": {
		spec{"xquq", op{0x0F, 0xF6}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xF6}, X, PREF_66, SSE2},
	},
	"pshufb": {
		spec{"xquq", op{0x0F, 0x38, 0x00}, X, DEFAULT, SSSE3 | MMX},
		spec{"yomq", op{0x0F, 0x38, 0x00}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x00}, X, PREF_66, SSSE3},
	},
	"pshufd": {
		spec{"yowoib", op{0x0F, 0x70}, X, PREF_66, SSE2},
	},
	"pshufhw": {
		spec{"yowoib", op{0x0F, 0x70}, X, PREF_F3, SSE2},
	},
	"pshuflw": {
		spec{"yowoib", op{0x0F, 0x70}, X, PREF_F2, SSE2},
	},
	"pshufw": {
		spec{"xquqib", op{0x0F, 0x70}, X, DEFAULT, MMX},
	},
	"psignb": {
		spec{"xquq", op{0x0F, 0x38, 0x08}, X, DEFAULT, MMX | SSSE3},
		spec{"yomq", op{0x0F, 0x38, 0x08}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x08}, X, PREF_66, SSSE3},
	},
	"psignd": {
		spec{"xquq", op{0x0F, 0x38, 0x0A}, X, DEFAULT, SSSE3 | MMX},
		spec{"yomq", op{0x0F, 0x38, 0x0A}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x0A}, X, PREF_66, SSSE3},
	},
	"psignw": {
		spec{"xquq", op{0x0F, 0x38, 0x09}, X, DEFAULT, MMX | SSSE3},
		spec{"yomq", op{0x0F, 0x38, 0x09}, X, PREF_66, SSSE3},
		spec{"yoyo", op{0x0F, 0x38, 0x09}, X, PREF_66, SSSE3},
	},
	"pslld": {
		spec{"xqib", op{0x0F, 0x72}, 6, DEFAULT, MMX},
		spec{"xquq", op{0x0F, 0xF2}, X, DEFAULT, MMX},
		spec{"yoib", op{0x0F, 0x72}, 6, PREF_66, SSE2},
		spec{"yowo", op{0x0F, 0xF2}, X, PREF_66, SSE2},
	},
	"pslldq": {
		spec{"yoib", op{0x0F, 0x73}, 7, PREF_66, SSE2},
	},
	"psllq": {
		spec{"xqib", op{0x0F, 0x73}, 6, DEFAULT, MMX},
		spec{"xquq", op{0x0F, 0xF3}, X, DEFAULT, MMX},
		spec{"yoib", op{0x0F, 0x73}, 6, PREF_66, SSE2},
		spec{"yowo", op{0x0F, 0xF3}, X, PREF_66, SSE2},
	},
	"psllw": {
		spec{"xqib", op{0x0F, 0x71}, 6, DEFAULT, MMX},
		spec{"xquq", op{0x0F, 0xF1}, X, DEFAULT, MMX},
		spec{"yoib", op{0x0F, 0x71}, 6, PREF_66, SSE2},
		spec{"yowo", op{0x0F, 0xF1}, X, PREF_66, SSE2},
	},
	"psrad": {
		spec{"xqib", op{0x0F, 0x72}, 4, DEFAULT, MMX},
		spec{"xquq", op{0x0F, 0xE2}, X, DEFAULT, MMX},
		spec{"yoib", op{0x0F, 0x72}, 4, PREF_66, SSE2},
		spec{"yowo", op{0x0F, 0xE2}, X, PREF_66, SSE2},
	},
	"psraw": {
		spec{"xqib", op{0x0F, 0x71}, 4, DEFAULT, MMX},
		spec{"xquq", op{0x0F, 0xE1}, X, DEFAULT, MMX},
		spec{"yoib", op{0x0F, 0x71}, 4, PREF_66, SSE2},
		spec{"yowo", op{0x0F, 0xE1}, X, PREF_66, SSE2},
	},
	"psrld": {
		spec{"xqib", op{0x0F, 0x72}, 2, DEFAULT, MMX},
		spec{"xquq", op{0x0F, 0xD2}, X, DEFAULT, MMX},
		spec{"yoib", op{0x0F, 0x72}, 2, PREF_66, SSE2},
		spec{"yowo", op{0x0F, 0xD2}, X, PREF_66, SSE2},
	},
	"psrldq": {
		spec{"yoib", op{0x0F, 0x73}, 3, PREF_66, SSE2},
	},
	"psrlq": {
		spec{"xqib", op{0x0F, 0x73}, 2, DEFAULT, MMX},
		spec{"xquq", op{0x0F, 0xD3}, X, DEFAULT, MMX},
		spec{"yoib", op{0x0F, 0x73}, 2, PREF_66, SSE2},
		spec{"yowo", op{0x0F, 0xD3}, X, PREF_66, SSE2},
	},
	"psrlw": {
		spec{"xqib", op{0x0F, 0x71}, 2, DEFAULT, MMX},
		spec{"xquq", op{0x0F, 0xD1}, X, DEFAULT, MMX},
		spec{"yoib", op{0x0F, 0x71}, 2, PREF_66, SSE2},
		spec{"yowo", op{0x0F, 0xD1}, X, PREF_66, SSE2},
	},
	"psubb": {
		spec{"xquq", op{0x0F, 0xF8}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xF8}, X, PREF_66, SSE2},
	},
	"psubd": {
		spec{"xquq", op{0x0F, 0xFA}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xFA}, X, PREF_66, SSE2},
	},
	"psubq": {
		spec{"xquq", op{0x0F, 0xFB}, X, DEFAULT, SSE2},
		spec{"yowo", op{0x0F, 0xFB}, X, PREF_66, SSE2},
	},
	"psubsb": {
		spec{"xquq", op{0x0F, 0xE8}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xE8}, X, PREF_66, SSE2},
	},
	"psubsiw": {
		spec{"xquq", op{0x0F, 0x55}, X, DEFAULT, CYRIX | MMX},
	},
	"psubsw": {
		spec{"xquq", op{0x0F, 0xE9}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xE9}, X, PREF_66, SSE2},
	},
	"psubusb": {
		spec{"xquq", op{0x0F, 0xD8}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xD8}, X, PREF_66, SSE2},
	},
	"psubusw": {
		spec{"xquq", op{0x0F, 0xD9}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xD9}, X, PREF_66, SSE2},
	},
	"psubw": {
		spec{"xquq", op{0x0F, 0xF9}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xF9}, X, PREF_66, SSE2},
	},
	"pswapd": {
		spec{"xquq", op{0x0F, 0x0F, 0xBB}, X, IMM_OP, TDNOW},
	},
	"ptest": {
		spec{"yomq", op{0x0F, 0x38, 0x17}, X, PREF_66, SSE41},
		spec{"yoyo", op{0x0F, 0x38, 0x17}, X, PREF_66, SSE41},
	},
	"punpckhbw": {
		spec{"xquq", op{0x0F, 0x68}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x68}, X, PREF_66, SSE2},
	},
	"punpckhdq": {
		spec{"xquq", op{0x0F, 0x6A}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x6A}, X, PREF_66, SSE2},
	},
	"punpckhqdq": {
		spec{"yowo", op{0x0F, 0x6D}, X, PREF_66, SSE2},
	},
	"punpckhwd": {
		spec{"xquq", op{0x0F, 0x69}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x69}, X, PREF_66, SSE2},
	},
	"punpcklbw": {
		spec{"xquq", op{0x0F, 0x60}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x60}, X, PREF_66, SSE2},
	},
	"punpckldq": {
		spec{"xquq", op{0x0F, 0x62}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x62}, X, PREF_66, SSE2},
	},
	"punpcklqdq": {
		spec{"yowo", op{0x0F, 0x6C}, X, PREF_66, SSE2},
	},
	"punpcklwd": {
		spec{"xquq", op{0x0F, 0x61}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0x61}, X, PREF_66, SSE2},
	},
	"push": {
		spec{"Qw", op{0x06}, X, X86_ONLY, X64_IMPLICIT},
		spec{"Rw", op{0x0E}, X, X86_ONLY, X64_IMPLICIT},
		spec{"Sw", op{0x16}, X, X86_ONLY, X64_IMPLICIT},
		spec{"Tw", op{0x1E}, X, X86_ONLY, X64_IMPLICIT},
		spec{"Uw", op{0x0F, 0xA0}, X, DEFAULT, X64_IMPLICIT},
		spec{"Vw", op{0x0F, 0xA8}, X, DEFAULT, X64_IMPLICIT},
		spec{"ib", op{0x6A}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"iw", op{0x68}, X, EXACT_SIZE | WORD_SIZE, X64_IMPLICIT},
		spec{"id", op{0x68}, X, DEFAULT, X64_IMPLICIT},
		spec{"r*", op{0x50}, X, AUTO_NO32 | SHORT_ARG, X64_IMPLICIT},
		spec{"v*", op{0xFF}, 6, AUTO_NO32, X64_IMPLICIT},
	},
	"pusha": {
		spec{"", op{0x60}, X, X86_ONLY | WORD_SIZE, X64_IMPLICIT},
	},
	"pushad": {
		spec{"", op{0x60}, X, X86_ONLY, X64_IMPLICIT},
	},
	"pushf": {
		spec{"", op{0x9C}, X, DEFAULT, X64_IMPLICIT},
	},
	"pushfq": {
		spec{"", op{0x9C}, X, DEFAULT, X64_IMPLICIT},
	},
	"pushfw": {
		spec{"", op{0x9C}, X, WORD_SIZE, X64_IMPLICIT},
	},
	"pxor": {
		spec{"xquq", op{0x0F, 0xEF}, X, DEFAULT, MMX},
		spec{"yowo", op{0x0F, 0xEF}, X, PREF_66, SSE2},
	},
	"rcl": {
		spec{"vbBb", op{0xD2}, 2, DEFAULT, X64_IMPLICIT},
		spec{"vbib", op{0xC0}, 2, DEFAULT, X64_IMPLICIT},
		spec{"v*Bb", op{0xD3}, 2, AUTO_SIZE, X64_IMPLICIT},
		spec{"v*ib", op{0xC1}, 2, AUTO_SIZE, X64_IMPLICIT},
	},
	"rcpps": {
		spec{"yowo", op{0x0F, 0x53}, X, DEFAULT, SSE},
	},
	"rcpss": {
		spec{"yomd", op{0x0F, 0x53}, X, PREF_F3, SSE},
		spec{"yoyo", op{0x0F, 0x53}, X, PREF_F3, SSE},
	},
	"rcr": {
		spec{"vbBb", op{0xD2}, 3, DEFAULT, X64_IMPLICIT},
		spec{"vbib", op{0xC0}, 3, DEFAULT, X64_IMPLICIT},
		spec{"v*Bb", op{0xD3}, 3, AUTO_SIZE, X64_IMPLICIT},
		spec{"v*ib", op{0xC1}, 3, AUTO_SIZE, X64_IMPLICIT},
	},
	"rdfsbase": {
		spec{"rd", op{0x0F, 0xAE}, 0, PREF_F3, X64_IMPLICIT},
		spec{"rq", op{0x0F, 0xAE}, 0, WITH_REXW | PREF_F3, X64_IMPLICIT},
	},
	"rdgsbase": {
		spec{"rd", op{0x0F, 0xAE}, 1, PREF_F3, X64_IMPLICIT},
		spec{"rq", op{0x0F, 0xAE}, 1, WITH_REXW | PREF_F3, X64_IMPLICIT},
	},
	"rdm": {
		spec{"", op{0x0F, 0x3A}, X, DEFAULT, CYRIX},
	},
	"rdmsr": {
		spec{"", op{0x0F, 0x32}, X, DEFAULT, X64_IMPLICIT},
	},
	"rdpid": {
		spec{"rq", op{0x0F, 0xC7}, 7, PREF_F3, X64_IMPLICIT},
	},
	"rdpkru": {
		spec{"", op{0x0F, 0x01, 0xEE}, X, DEFAULT, X64_IMPLICIT},
	},
	"rdpmc": {
		spec{"", op{0x0F, 0x33}, X, DEFAULT, X64_IMPLICIT},
	},
	"rdrand": {
		spec{"rq", op{0x0F, 0xC7}, 6, WITH_REXW, X64_IMPLICIT},
	},
	"rdseed": {
		spec{"rq", op{0x0F, 0xC7}, 7, WITH_REXW, X64_IMPLICIT},
	},
	"rdshr": {
		spec{"vd", op{0x0F, 0x36}, 0, DEFAULT, CYRIX},
	},
	"rdtsc": {
		spec{"", op{0x0F, 0x31}, X, DEFAULT, X64_IMPLICIT},
	},
	"rdtscp": {
		spec{"", op{0x0F, 0x01, 0xF9}, X, DEFAULT, X64_IMPLICIT},
	},
	"ret": {
		spec{"", op{0xC3}, X, DEFAULT, X64_IMPLICIT},
		spec{"iw", op{0xC2}, X, DEFAULT, X64_IMPLICIT},
	},
	"retf": {
		spec{"", op{0xCB}, X, DEFAULT, X64_IMPLICIT},
		spec{"iw", op{0xCA}, X, DEFAULT, X64_IMPLICIT},
	},
	"retn": {
		spec{"", op{0xC3}, X, DEFAULT, X64_IMPLICIT},
		spec{"iw", op{0xC2}, X, DEFAULT, X64_IMPLICIT},
	},
	"rol": {
		spec{"vbBb", op{0xD2}, 0, DEFAULT, X64_IMPLICIT},
		spec{"vbib", op{0xC0}, 0, DEFAULT, X64_IMPLICIT},
		spec{"v*Bb", op{0xD3}, 0, AUTO_SIZE, X64_IMPLICIT},
		spec{"v*ib", op{0xC1}, 0, AUTO_SIZE, X64_IMPLICIT},
	},
	"ror": {
		spec{"vbBb", op{0xD2}, 1, DEFAULT, X64_IMPLICIT},
		spec{"vbib", op{0xC0}, 1, DEFAULT, X64_IMPLICIT},
		spec{"v*Bb", op{0xD3}, 1, AUTO_SIZE, X64_IMPLICIT},
		spec{"v*ib", op{0xC1}, 1, AUTO_SIZE, X64_IMPLICIT},
	},
	"rorx": {
		spec{"r*v*ib", op{0x03, 0xF0}, X, VEX_OP | AUTO_REXW | PREF_F2, BMI2},
	},
	"roundpd": {
		spec{"yomqib", op{0x0F, 0x3A, 0x09}, X, PREF_66, SSE41},
		spec{"yoyoib", op{0x0F, 0x3A, 0x09}, X, PREF_66, SSE41},
	},
	"roundps": {
		spec{"yomqib", op{0x0F, 0x3A, 0x08}, X, PREF_66, SSE41},
		spec{"yoyoib", op{0x0F, 0x3A, 0x08}, X, PREF_66, SSE41},
	},
	"roundsd": {
		spec{"yomqib", op{0x0F, 0x3A, 0x0B}, X, PREF_66, SSE41},
		spec{"yoyoib", op{0x0F, 0x3A, 0x0B}, X, PREF_66, SSE41},
	},
	"roundss": {
		spec{"yomqib", op{0x0F, 0x3A, 0x0A}, X, PREF_66, SSE41},
		spec{"yoyoib", op{0x0F, 0x3A, 0x0A}, X, PREF_66, SSE41},
	},
	"rsdc": {
		spec{"swmp", op{0x0F, 0x79}, X, EXACT_SIZE, CYRIX},
	},
	"rsldt": {
		spec{"mp", op{0x0F, 0x7B}, 0, EXACT_SIZE, CYRIX},
	},
	"rsm": {
		spec{"", op{0x0F, 0xAA}, X, DEFAULT, X64_IMPLICIT},
	},
	"rsqrtps": {
		spec{"yowo", op{0x0F, 0x52}, X, DEFAULT, SSE},
	},
	"rsqrtss": {
		spec{"yomd", op{0x0F, 0x52}, X, PREF_F3, SSE},
		spec{"yoyo", op{0x0F, 0x52}, X, PREF_F3, SSE},
	},
	"rsts": {
		spec{"mp", op{0x0F, 0x7D}, 0, EXACT_SIZE, CYRIX},
	},
	"sahf": {
		spec{"", op{0x9E}, X, DEFAULT, X64_IMPLICIT},
	},
	"sal": {
		spec{"vbBb", op{0xD2}, 4, DEFAULT, X64_IMPLICIT},
		spec{"vbib", op{0xC0}, 4, DEFAULT, X64_IMPLICIT},
		spec{"v*Bb", op{0xD3}, 4, AUTO_SIZE, X64_IMPLICIT},
		spec{"v*ib", op{0xC1}, 4, AUTO_SIZE, X64_IMPLICIT},
	},
	"sar": {
		spec{"vbBb", op{0xD2}, 7, DEFAULT, X64_IMPLICIT},
		spec{"vbib", op{0xC0}, 7, DEFAULT, X64_IMPLICIT},
		spec{"v*Bb", op{0xD3}, 7, AUTO_SIZE, X64_IMPLICIT},
		spec{"v*ib", op{0xC1}, 7, AUTO_SIZE, X64_IMPLICIT},
	},
	"sarx": {
		spec{"r*v*r*", op{0x02, 0xF7}, X, VEX_OP | AUTO_REXW | ENC_MR | PREF_F3, BMI2},
	},
	"sbb": {
		spec{"Abib", op{0x1C}, X, DEFAULT, X64_IMPLICIT},
		spec{"mbib", op{0x80}, 3, LOCK, X64_IMPLICIT},
		spec{"mbrb", op{0x18}, X, LOCK | ENC_MR, X64_IMPLICIT},
		spec{"rbib", op{0x80}, 3, DEFAULT, X64_IMPLICIT},
		spec{"rbrb", op{0x18}, X, ENC_MR, X64_IMPLICIT},
		spec{"rbvb", op{0x1A}, X, DEFAULT, X64_IMPLICIT},
		spec{"r*ib", op{0x83}, 3, AUTO_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"A*i*", op{0x1D}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"m*i*", op{0x81}, 3, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*ib", op{0x83}, 3, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*r*", op{0x19}, X, AUTO_SIZE | LOCK | ENC_MR, X64_IMPLICIT},
		spec{"r*i*", op{0x81}, 3, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*r*", op{0x19}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
		spec{"r*v*", op{0x1B}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"scasb": {
		spec{"", op{0xAE}, X, REPE, X64_IMPLICIT},
	},
	"scasd": {
		spec{"", op{0xAF}, X, REPE, X64_IMPLICIT},
	},
	"scasq": {
		spec{"", op{0xAF}, X, REPE | WITH_REXW, X64_IMPLICIT},
	},
	"scasw": {
		spec{"", op{0xAF}, X, REPE | WORD_SIZE, X64_IMPLICIT},
	},
	"sfence": {
		spec{"", op{0x0F, 0xAE, 0xF8}, X, DEFAULT, AMD},
	},
	"sgdt": {
		spec{"m!", op{0x0F, 0x01}, 0, DEFAULT, X64_IMPLICIT},
	},
	"sha1msg1": {
		spec{"yowo", op{0x0F, 0x38, 0xC9}, X, DEFAULT, SHA},
	},
	"sha1msg2": {
		spec{"yowo", op{0x0F, 0x38, 0xCA}, X, DEFAULT, SHA},
	},
	"sha1nexte": {
		spec{"yowo", op{0x0F, 0x38, 0xC8}, X, DEFAULT, SHA},
	},
	"sha1rnds4": {
		spec{"yowoib", op{0x0F, 0x3A, 0xCC}, X, DEFAULT, SHA},
	},
	"sha256msg1": {
		spec{"yowo", op{0x0F, 0x38, 0xCC}, X, DEFAULT, SHA},
	},
	"sha256msg2": {
		spec{"yowo", op{0x0F, 0x38, 0xCD}, X, DEFAULT, SHA},
	},
	"sha256rnds2": {
		spec{"yowo", op{0x0F, 0x38, 0xCB}, X, DEFAULT, SHA},
	},
	"shl": {
		spec{"vbBb", op{0xD2}, 4, DEFAULT, X64_IMPLICIT},
		spec{"vbib", op{0xC0}, 4, DEFAULT, X64_IMPLICIT},
		spec{"v*Bb", op{0xD3}, 4, AUTO_SIZE, X64_IMPLICIT},
		spec{"v*ib", op{0xC1}, 4, AUTO_SIZE, X64_IMPLICIT},
	},
	"shld": {
		spec{"v*r*Bb", op{0x0F, 0xA5}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
		spec{"v*r*ib", op{0x0F, 0xA4}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
	},
	"shlx": {
		spec{"r*v*r*", op{0x02, 0xF7}, X, VEX_OP | AUTO_REXW | ENC_MR | PREF_66, BMI2},
	},
	"shr": {
		spec{"vbBb", op{0xD2}, 5, DEFAULT, X64_IMPLICIT},
		spec{"vbib", op{0xC0}, 5, DEFAULT, X64_IMPLICIT},
		spec{"v*Bb", op{0xD3}, 5, AUTO_SIZE, X64_IMPLICIT},
		spec{"v*ib", op{0xC1}, 5, AUTO_SIZE, X64_IMPLICIT},
	},
	"shrd": {
		spec{"v*r*Bb", op{0x0F, 0xAD}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
		spec{"v*r*ib", op{0x0F, 0xAC}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
	},
	"shrx": {
		spec{"r*v*r*", op{0x02, 0xF7}, X, VEX_OP | AUTO_REXW | ENC_MR | PREF_F2, BMI2},
	},
	"shufpd": {
		spec{"yowoib", op{0x0F, 0xC6}, X, PREF_66, SSE2},
	},
	"shufps": {
		spec{"yowoib", op{0x0F, 0xC6}, X, DEFAULT, SSE},
	},
	"sidt": {
		spec{"m!", op{0x0F, 0x01}, 1, DEFAULT, X64_IMPLICIT},
	},
	"skinit": {
		spec{"", op{0x0F, 0x01, 0xDE}, X, DEFAULT, X64_IMPLICIT},
	},
	"sldt": {
		spec{"m!", op{0x0F, 0x00}, 0, DEFAULT, X64_IMPLICIT},
		spec{"r*", op{0x0F, 0x00}, 0, AUTO_SIZE, X64_IMPLICIT},
	},
	"slwpcb": {
		spec{"r*", op{0x09, 0x12}, 1, XOP_OP | AUTO_REXW, AMD},
	},
	"smint": {
		spec{"", op{0x0F, 0x38}, X, DEFAULT, CYRIX},
	},
	"smsw": {
		spec{"m!", op{0x0F, 0x01}, 4, DEFAULT, X64_IMPLICIT},
		spec{"r*", op{0x0F, 0x01}, 4, AUTO_SIZE, X64_IMPLICIT},
	},
	"sqrtpd": {
		spec{"yowo", op{0x0F, 0x51}, X, PREF_66, SSE2},
	},
	"sqrtps": {
		spec{"yowo", op{0x0F, 0x51}, X, DEFAULT, SSE},
	},
	"sqrtsd": {
		spec{"yomq", op{0x0F, 0x51}, X, PREF_F2, SSE2},
		spec{"yoyo", op{0x0F, 0x51}, X, PREF_F2, SSE2},
	},
	"sqrtss": {
		spec{"yomd", op{0x0F, 0x51}, X, PREF_F3, SSE},
		spec{"yoyo", op{0x0F, 0x51}, X, PREF_F3, SSE},
	},
	"stac": {
		spec{"", op{0x0F, 0x01, 0xCB}, X, DEFAULT, X64_IMPLICIT},
	},
	"stc": {
		spec{"", op{0xF9}, X, DEFAULT, X64_IMPLICIT},
	},
	"std": {
		spec{"", op{0xFD}, X, DEFAULT, X64_IMPLICIT},
	},
	"stgi": {
		spec{"", op{0x0F, 0x01, 0xDC}, X, DEFAULT, VMX | AMD},
	},
	"sti": {
		spec{"", op{0xFB}, X, DEFAULT, X64_IMPLICIT},
	},
	"stmxcsr": {
		spec{"md", op{0x0F, 0xAE}, 3, DEFAULT, SSE},
	},
	"stosb": {
		spec{"", op{0xAA}, X, REP, X64_IMPLICIT},
	},
	"stosd": {
		spec{"", op{0xAB}, X, REP, X64_IMPLICIT},
	},
	"stosq": {
		spec{"", op{0xAB}, X, WITH_REXW | REP, X64_IMPLICIT},
	},
	"stosw": {
		spec{"", op{0xAB}, X, WORD_SIZE | REP, X64_IMPLICIT},
	},
	"str": {
		spec{"m!", op{0x0F, 0x00}, 1, DEFAULT, X64_IMPLICIT},
		spec{"r*", op{0x0F, 0x00}, 1, AUTO_SIZE, X64_IMPLICIT},
	},
	"sub": {
		spec{"Abib", op{0x2C}, X, DEFAULT, X64_IMPLICIT},
		spec{"mbib", op{0x80}, 5, LOCK, X64_IMPLICIT},
		spec{"mbrb", op{0x28}, X, LOCK | ENC_MR, X64_IMPLICIT},
		spec{"rbib", op{0x80}, 5, DEFAULT, X64_IMPLICIT},
		spec{"rbrb", op{0x28}, X, ENC_MR, X64_IMPLICIT},
		spec{"rbvb", op{0x2A}, X, DEFAULT, X64_IMPLICIT},
		spec{"r*ib", op{0x83}, 5, AUTO_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"A*i*", op{0x2D}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"m*i*", op{0x81}, 5, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*ib", op{0x83}, 5, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*r*", op{0x29}, X, AUTO_SIZE | LOCK | ENC_MR, X64_IMPLICIT},
		spec{"r*i*", op{0x81}, 5, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*r*", op{0x29}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
		spec{"r*v*", op{0x2B}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"subpd": {
		spec{"yowo", op{0x0F, 0x5C}, X, PREF_66, SSE2},
	},
	"subps": {
		spec{"yowo", op{0x0F, 0x5C}, X, DEFAULT, SSE},
	},
	"subsd": {
		spec{"yomq", op{0x0F, 0x5C}, X, PREF_F2, SSE2},
		spec{"yoyo", op{0x0F, 0x5C}, X, PREF_F2, SSE2},
	},
	"subss": {
		spec{"yomd", op{0x0F, 0x5C}, X, PREF_F3, SSE},
		spec{"yoyo", op{0x0F, 0x5C}, X, PREF_F3, SSE},
	},
	"svdc": {
		spec{"mpsw", op{0x0F, 0x78}, X, ENC_MR | EXACT_SIZE, CYRIX},
	},
	"svldt": {
		spec{"mp", op{0x0F, 0x7A}, 0, EXACT_SIZE, CYRIX},
	},
	"svts": {
		spec{"mp", op{0x0F, 0x7C}, 0, EXACT_SIZE, CYRIX},
	},
	"swapgs": {
		spec{"", op{0x0F, 0x01, 0xF8}, X, DEFAULT, X64_IMPLICIT},
	},
	"syscall": {
		spec{"", op{0x0F, 0x05}, X, DEFAULT, AMD},
	},
	"sysenter": {
		spec{"", op{0x0F, 0x34}, X, X86_ONLY, X64_IMPLICIT},
	},
	"sysexit": {
		spec{"", op{0x0F, 0x35}, X, X86_ONLY, X64_IMPLICIT},
	},
	"sysret": {
		spec{"", op{0x0F, 0x07}, X, DEFAULT, AMD},
	},
	"t1mskc": {
		spec{"r*v*", op{0x09, 0x01}, 7, XOP_OP | AUTO_REXW | ENC_VM, TBM},
	},
	"test": {
		spec{"Abib", op{0xA8}, X, DEFAULT, X64_IMPLICIT},
		spec{"rbmb", op{0x84}, X, DEFAULT, X64_IMPLICIT},
		spec{"vbib", op{0xF6}, 0, DEFAULT, X64_IMPLICIT},
		spec{"vbrb", op{0x84}, X, ENC_MR, X64_IMPLICIT},
		spec{"A*i*", op{0xA9}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*m*", op{0x85}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"v*i*", op{0xF7}, 0, AUTO_SIZE, X64_IMPLICIT},
		spec{"v*r*", op{0x85}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
	},
	"tzcnt": {
		spec{"r*v*", op{0x0F, 0xBC}, X, AUTO_SIZE | PREF_F3, BMI1},
	},
	"tzmsk": {
		spec{"r*v*", op{0x09, 0x01}, 4, XOP_OP | AUTO_REXW | ENC_VM, TBM},
	},
	"ucomisd": {
		spec{"yomq", op{0x0F, 0x2E}, X, PREF_66, SSE2},
		spec{"yoyo", op{0x0F, 0x2E}, X, PREF_66, SSE2},
	},
	"ucomiss": {
		spec{"yomd", op{0x0F, 0x2E}, X, DEFAULT, SSE},
		spec{"yoyo", op{0x0F, 0x2E}, X, DEFAULT, SSE},
	},
	"ud2": {
		spec{"", op{0x0F, 0x0B}, X, DEFAULT, X64_IMPLICIT},
	},
	"ud2a": {
		spec{"", op{0x0F, 0x0B}, X, DEFAULT, X64_IMPLICIT},
	},
	"unpckhpd": {
		spec{"yowo", op{0x0F, 0x15}, X, PREF_66, SSE2},
	},
	"unpckhps": {
		spec{"yowo", op{0x0F, 0x15}, X, DEFAULT, SSE},
	},
	"unpcklpd": {
		spec{"yowo", op{0x0F, 0x14}, X, PREF_66, SSE2},
	},
	"unpcklps": {
		spec{"yowo", op{0x0F, 0x14}, X, DEFAULT, SSE},
	},
	"vaddpd": {
		spec{"y*y*w*", op{0x01, 0x58}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vaddps": {
		spec{"y*y*w*", op{0x01, 0x58}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vaddsd": {
		spec{"yoyomq", op{0x01, 0x58}, X, VEX_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0x58}, X, VEX_OP | PREF_F2, AVX},
	},
	"vaddss": {
		spec{"yoyomd", op{0x01, 0x58}, X, VEX_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0x58}, X, VEX_OP | PREF_F3, AVX},
	},
	"vaddsubpd": {
		spec{"y*y*w*", op{0x01, 0xD0}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vaddsubps": {
		spec{"y*y*w*", op{0x01, 0xD0}, X, VEX_OP | AUTO_VEXL | PREF_F2, AVX},
	},
	"vaesdec": {
		spec{"yoyowo", op{0x02, 0xDE}, X, VEX_OP | PREF_66, AVX},
	},
	"vaesdeclast": {
		spec{"yoyowo", op{0x02, 0xDF}, X, VEX_OP | PREF_66, AVX},
	},
	"vaesenc": {
		spec{"yoyowo", op{0x02, 0xDC}, X, VEX_OP | PREF_66, AVX},
	},
	"vaesenclast": {
		spec{"yoyowo", op{0x02, 0xDD}, X, VEX_OP | PREF_66, AVX},
	},
	"vaesimc": {
		spec{"yowo", op{0x02, 0xDB}, X, VEX_OP | PREF_66, AVX},
	},
	"vaeskeygenassist": {
		spec{"yowoib", op{0x03, 0xDF}, X, VEX_OP | PREF_66, AVX},
	},
	"vandnpd": {
		spec{"y*y*w*", op{0x01, 0x55}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vandnps": {
		spec{"y*y*w*", op{0x01, 0x55}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vandpd": {
		spec{"y*y*w*", op{0x01, 0x54}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vandps": {
		spec{"y*y*w*", op{0x01, 0x54}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vblendpd": {
		spec{"y*y*w*ib", op{0x03, 0x0D}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX},
	},
	"vblendps": {
		spec{"y*y*w*ib", op{0x03, 0x0C}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX},
	},
	"vblendvpd": {
		spec{"y*y*w*y*", op{0x03, 0x4B}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vblendvps": {
		spec{"y*y*w*y*", op{0x03, 0x4A}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vbroadcastf128": {
		spec{"yhmo", op{0x02, 0x1A}, X, WITH_VEXL | VEX_OP | PREF_66, AVX},
	},
	"vbroadcasti128": {
		spec{"yhmo", op{0x02, 0x5A}, X, WITH_VEXL | VEX_OP | PREF_66, AVX2},
	},
	"vbroadcastsd": {
		spec{"yhmq", op{0x02, 0x19}, X, VEX_OP | WITH_VEXL | PREF_66, AVX},
		spec{"yhyo", op{0x02, 0x19}, X, VEX_OP | WITH_VEXL | PREF_66, AVX},
	},
	"vbroadcastss": {
		spec{"y*md", op{0x02, 0x18}, X, VEX_OP | PREF_66, AVX},
		spec{"y*yo", op{0x02, 0x18}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vcmpeq_ospd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x10}, X, VEX_OP | PREF_66 | IMM_OP, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x10}, X, VEX_OP | IMM_OP | PREF_66, AVX},
	},
	"vcmpeq_osps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x10}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpeq_ossd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x10}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x10}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpeq_osss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x10}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x10}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpeq_uqpd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x08}, X, WITH_VEXL | VEX_OP | IMM_OP | PREF_66, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x08}, X, VEX_OP | PREF_66 | IMM_OP, AVX},
	},
	"vcmpeq_uqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x08}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpeq_uqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x08}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x08}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpeq_uqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x08}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x08}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpeq_uspd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x18}, X, WITH_VEXL | VEX_OP | IMM_OP | PREF_66, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x18}, X, VEX_OP | PREF_66 | IMM_OP, AVX},
	},
	"vcmpeq_usps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x18}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpeq_ussd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x18}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x18}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpeq_usss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x18}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x18}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpeqpd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x00}, X, VEX_OP | AUTO_VEXL | IMM_OP | PREF_66, AVX},
	},
	"vcmpeqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x00}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpeqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x00}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x00}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpeqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x00}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x00}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpfalse_oqpd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0B}, X, VEX_OP | AUTO_VEXL | IMM_OP | PREF_66, AVX},
	},
	"vcmpfalse_oqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0B}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpfalse_oqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0B}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0B}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpfalse_oqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0B}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0B}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpfalse_ospd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x1B}, X, VEX_OP | AUTO_VEXL | PREF_66 | IMM_OP, AVX},
	},
	"vcmpfalse_osps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x1B}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpfalse_ossd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x1B}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x1B}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpfalse_osss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x1B}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x1B}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpfalsepd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x0B}, X, WITH_VEXL | VEX_OP | PREF_66 | IMM_OP, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x0B}, X, VEX_OP | IMM_OP | PREF_66, AVX},
	},
	"vcmpfalseps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0B}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpfalsesd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0B}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0B}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpfalsess": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0B}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0B}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpge_oqpd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x1D}, X, WITH_VEXL | VEX_OP | PREF_66 | IMM_OP, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x1D}, X, VEX_OP | IMM_OP | PREF_66, AVX},
	},
	"vcmpge_oqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x1D}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpge_oqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x1D}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x1D}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpge_oqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x1D}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x1D}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpge_ospd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0D}, X, VEX_OP | AUTO_VEXL | PREF_66 | IMM_OP, AVX},
	},
	"vcmpge_osps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0D}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpge_ossd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0D}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0D}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpge_osss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0D}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0D}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpgepd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0D}, X, VEX_OP | AUTO_VEXL | IMM_OP | PREF_66, AVX},
	},
	"vcmpgeps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0D}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpgesd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0D}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0D}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpgess": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0D}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0D}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpgt_oqpd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x1E}, X, VEX_OP | AUTO_VEXL | IMM_OP | PREF_66, AVX},
	},
	"vcmpgt_oqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x1E}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpgt_oqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x1E}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x1E}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpgt_oqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x1E}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x1E}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpgt_ospd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0E}, X, VEX_OP | AUTO_VEXL | IMM_OP | PREF_66, AVX},
	},
	"vcmpgt_osps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0E}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpgt_ossd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0E}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0E}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpgt_osss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0E}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0E}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpgtpd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x0E}, X, WITH_VEXL | VEX_OP | PREF_66 | IMM_OP, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x0E}, X, VEX_OP | IMM_OP | PREF_66, AVX},
	},
	"vcmpgtps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0E}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpgtsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0E}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0E}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpgtss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0E}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0E}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmple_oqpd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x12}, X, WITH_VEXL | VEX_OP | IMM_OP | PREF_66, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x12}, X, VEX_OP | PREF_66 | IMM_OP, AVX},
	},
	"vcmple_oqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x12}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmple_oqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x12}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x12}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmple_oqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x12}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x12}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmple_ospd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x02}, X, VEX_OP | AUTO_VEXL | IMM_OP | PREF_66, AVX},
	},
	"vcmple_osps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x02}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmple_ossd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x02}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x02}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmple_osss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x02}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x02}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmplepd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x02}, X, WITH_VEXL | VEX_OP | IMM_OP | PREF_66, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x02}, X, VEX_OP | PREF_66 | IMM_OP, AVX},
	},
	"vcmpleps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x02}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmplesd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x02}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x02}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpless": {
		spec{"yoyomq", op{0x01, 0xC2, 0x02}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x02}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmplt_oqpd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x11}, X, VEX_OP | AUTO_VEXL | PREF_66 | IMM_OP, AVX},
	},
	"vcmplt_oqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x11}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmplt_oqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x11}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x11}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmplt_oqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x11}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x11}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmplt_ospd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x01}, X, WITH_VEXL | VEX_OP | IMM_OP | PREF_66, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x01}, X, VEX_OP | PREF_66 | IMM_OP, AVX},
	},
	"vcmplt_osps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x01}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmplt_ossd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x01}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x01}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmplt_osss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x01}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x01}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpltpd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x01}, X, WITH_VEXL | VEX_OP | IMM_OP | PREF_66, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x01}, X, VEX_OP | PREF_66 | IMM_OP, AVX},
	},
	"vcmpltps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x01}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpltsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x01}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x01}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpltss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x01}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x01}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpneq_oqpd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x0C}, X, WITH_VEXL | VEX_OP | IMM_OP | PREF_66, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x0C}, X, VEX_OP | PREF_66 | IMM_OP, AVX},
	},
	"vcmpneq_oqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0C}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpneq_oqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0C}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0C}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpneq_oqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0C}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0C}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpneq_ospd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x1C}, X, WITH_VEXL | VEX_OP | PREF_66 | IMM_OP, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x1C}, X, VEX_OP | IMM_OP | PREF_66, AVX},
	},
	"vcmpneq_osps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x1C}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpneq_ossd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x1C}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x1C}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpneq_osss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x1C}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x1C}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpneq_uqpd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x04}, X, VEX_OP | AUTO_VEXL | PREF_66 | IMM_OP, AVX},
	},
	"vcmpneq_uqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x04}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpneq_uqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x04}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x04}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpneq_uqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x04}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x04}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpneq_uspd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x14}, X, WITH_VEXL | VEX_OP | IMM_OP | PREF_66, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x14}, X, VEX_OP | PREF_66 | IMM_OP, AVX},
	},
	"vcmpneq_usps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x14}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpneq_ussd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x14}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x14}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpneq_usss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x14}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x14}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpneqpd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x04}, X, WITH_VEXL | VEX_OP | PREF_66 | IMM_OP, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x04}, X, VEX_OP | IMM_OP | PREF_66, AVX},
	},
	"vcmpneqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x04}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpneqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x04}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x04}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpneqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x04}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x04}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpnge_uqpd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x19}, X, VEX_OP | AUTO_VEXL | PREF_66 | IMM_OP, AVX},
	},
	"vcmpnge_uqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x19}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpnge_uqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x19}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x19}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpnge_uqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x19}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x19}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpnge_uspd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x09}, X, VEX_OP | AUTO_VEXL | IMM_OP | PREF_66, AVX},
	},
	"vcmpnge_usps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x09}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpnge_ussd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x09}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x09}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpnge_usss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x09}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x09}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpngepd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x09}, X, WITH_VEXL | VEX_OP | PREF_66 | IMM_OP, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x09}, X, VEX_OP | IMM_OP | PREF_66, AVX},
	},
	"vcmpngeps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x09}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpngesd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x09}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x09}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpngess": {
		spec{"yoyomq", op{0x01, 0xC2, 0x09}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x09}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpngt_uqpd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x1A}, X, VEX_OP | AUTO_VEXL | PREF_66 | IMM_OP, AVX},
	},
	"vcmpngt_uqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x1A}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpngt_uqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x1A}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x1A}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpngt_uqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x1A}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x1A}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpngt_uspd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0A}, X, VEX_OP | AUTO_VEXL | PREF_66 | IMM_OP, AVX},
	},
	"vcmpngt_usps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0A}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpngt_ussd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0A}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0A}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpngt_usss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0A}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0A}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpngtpd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0A}, X, VEX_OP | AUTO_VEXL | IMM_OP | PREF_66, AVX},
	},
	"vcmpngtps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0A}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpngtsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0A}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0A}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpngtss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0A}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0A}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpnle_uqpd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x16}, X, VEX_OP | AUTO_VEXL | PREF_66 | IMM_OP, AVX},
	},
	"vcmpnle_uqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x16}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpnle_uqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x16}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x16}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpnle_uqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x16}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x16}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpnle_uspd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x06}, X, WITH_VEXL | VEX_OP | IMM_OP | PREF_66, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x06}, X, VEX_OP | PREF_66 | IMM_OP, AVX},
	},
	"vcmpnle_usps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x06}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpnle_ussd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x06}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x06}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpnle_usss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x06}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x06}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpnlepd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x06}, X, VEX_OP | AUTO_VEXL | IMM_OP | PREF_66, AVX},
	},
	"vcmpnleps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x06}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpnlesd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x06}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x06}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpnless": {
		spec{"yoyomq", op{0x01, 0xC2, 0x06}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x06}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpnlt_uqpd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x15}, X, WITH_VEXL | VEX_OP | IMM_OP | PREF_66, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x15}, X, VEX_OP | PREF_66 | IMM_OP, AVX},
	},
	"vcmpnlt_uqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x15}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpnlt_uqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x15}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x15}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpnlt_uqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x15}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x15}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpnlt_uspd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x05}, X, VEX_OP | AUTO_VEXL | IMM_OP | PREF_66, AVX},
	},
	"vcmpnlt_usps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x05}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpnlt_ussd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x05}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x05}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpnlt_usss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x05}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x05}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpnltpd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x05}, X, WITH_VEXL | VEX_OP | PREF_66 | IMM_OP, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x05}, X, VEX_OP | IMM_OP | PREF_66, AVX},
	},
	"vcmpnltps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x05}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpnltsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x05}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x05}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpnltss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x05}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x05}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpord_qpd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x07}, X, WITH_VEXL | VEX_OP | PREF_66 | IMM_OP, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x07}, X, VEX_OP | IMM_OP | PREF_66, AVX},
	},
	"vcmpord_qps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x07}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpord_qsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x07}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x07}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpord_qss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x07}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x07}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpord_spd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x17}, X, WITH_VEXL | VEX_OP | PREF_66 | IMM_OP, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x17}, X, VEX_OP | IMM_OP | PREF_66, AVX},
	},
	"vcmpord_sps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x17}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpord_ssd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x17}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x17}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpord_sss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x17}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x17}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpordpd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x07}, X, WITH_VEXL | VEX_OP | IMM_OP | PREF_66, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x07}, X, VEX_OP | PREF_66 | IMM_OP, AVX},
	},
	"vcmpordps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x07}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpordsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x07}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x07}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpordss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x07}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x07}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmppd": {
		spec{"y*y*w*ib", op{0x01, 0xC2}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX},
	},
	"vcmpps": {
		spec{"y*y*w*ib", op{0x01, 0xC2}, X, VEX_OP | AUTO_VEXL | ENC_MR, AVX},
	},
	"vcmpsd": {
		spec{"yoyomqib", op{0x01, 0xC2}, X, VEX_OP | PREF_F2, AVX},
		spec{"yoyoyoib", op{0x01, 0xC2}, X, VEX_OP | PREF_F2, AVX},
	},
	"vcmpss": {
		spec{"yoyomqib", op{0x01, 0xC2}, X, VEX_OP | PREF_F3, AVX},
		spec{"yoyoyoib", op{0x01, 0xC2}, X, VEX_OP | PREF_F3, AVX},
	},
	"vcmptrue_uqpd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x0F}, X, WITH_VEXL | VEX_OP | IMM_OP | PREF_66, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x0F}, X, VEX_OP | PREF_66 | IMM_OP, AVX},
	},
	"vcmptrue_uqps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0F}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmptrue_uqsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0F}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0F}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmptrue_uqss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0F}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0F}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmptrue_uspd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x1F}, X, VEX_OP | AUTO_VEXL | PREF_66 | IMM_OP, AVX},
	},
	"vcmptrue_usps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x1F}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmptrue_ussd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x1F}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x1F}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmptrue_usss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x1F}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x1F}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmptruepd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0F}, X, VEX_OP | AUTO_VEXL | PREF_66 | IMM_OP, AVX},
	},
	"vcmptrueps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x0F}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmptruesd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0F}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0F}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmptruess": {
		spec{"yoyomq", op{0x01, 0xC2, 0x0F}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x0F}, X, VEX_OP | PREF_F3 | IMM_OP, AVX},
	},
	"vcmpunord_qpd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x03}, X, VEX_OP | AUTO_VEXL | PREF_66 | IMM_OP, AVX},
	},
	"vcmpunord_qps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x03}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpunord_qsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x03}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x03}, X, VEX_OP | IMM_OP | PREF_F2, AVX},
	},
	"vcmpunord_qss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x03}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x03}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpunord_spd": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x13}, X, VEX_OP | AUTO_VEXL | IMM_OP | PREF_66, AVX},
	},
	"vcmpunord_sps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x13}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpunord_ssd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x13}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x13}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpunord_sss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x13}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x13}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcmpunordpd": {
		spec{"yhyhwh", op{0x01, 0xC2, 0x03}, X, WITH_VEXL | VEX_OP | PREF_66 | IMM_OP, AVX},
		spec{"yoyowo", op{0x01, 0xC2, 0x03}, X, VEX_OP | IMM_OP | PREF_66, AVX},
	},
	"vcmpunordps": {
		spec{"y*y*w*", op{0x01, 0xC2, 0x03}, X, VEX_OP | AUTO_VEXL | IMM_OP, AVX},
	},
	"vcmpunordsd": {
		spec{"yoyomq", op{0x01, 0xC2, 0x03}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x03}, X, VEX_OP | PREF_F2 | IMM_OP, AVX},
	},
	"vcmpunordss": {
		spec{"yoyomq", op{0x01, 0xC2, 0x03}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0xC2, 0x03}, X, VEX_OP | IMM_OP | PREF_F3, AVX},
	},
	"vcomisd": {
		spec{"yomq", op{0x01, 0x2F}, X, VEX_OP | PREF_66, AVX},
		spec{"yoyo", op{0x01, 0x2F}, X, VEX_OP | PREF_66, AVX},
	},
	"vcomiss": {
		spec{"yomd", op{0x01, 0x2F}, X, VEX_OP, AVX},
		spec{"yoyo", op{0x01, 0x2F}, X, VEX_OP, AVX},
	},
	"vcvtdq2pd": {
		spec{"yomq", op{0x01, 0xE6}, X, VEX_OP | PREF_F3, AVX},
		spec{"y*wo", op{0x01, 0xE6}, X, VEX_OP | AUTO_VEXL | PREF_F3, AVX},
	},
	"vcvtdq2ps": {
		spec{"y*w*", op{0x01, 0x5B}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vcvtpd2dq": {
		spec{"yom*", op{0x01, 0xE6}, X, VEX_OP | AUTO_VEXL | PREF_F2, AVX},
		spec{"yoy*", op{0x01, 0xE6}, X, VEX_OP | AUTO_VEXL | PREF_F2, AVX},
	},
	"vcvtpd2ps": {
		spec{"yom*", op{0x01, 0x5A}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
		spec{"yoy*", op{0x01, 0x5A}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vcvtph2ps": {
		spec{"yomq", op{0x02, 0x13}, X, VEX_OP | PREF_66, AVX},
		spec{"y*wo", op{0x02, 0x13}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vcvtps2dq": {
		spec{"y*w*", op{0x01, 0x5B}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vcvtps2pd": {
		spec{"yomq", op{0x01, 0x5A}, X, VEX_OP, AVX},
		spec{"y*wo", op{0x01, 0x5A}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vcvtps2ph": {
		spec{"mqyoib", op{0x03, 0x1D}, X, VEX_OP | ENC_MR | PREF_66, AVX},
		spec{"woy*ib", op{0x03, 0x1D}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX},
	},
	"vcvtsd2si": {
		spec{"r*mq", op{0x01, 0x2D}, X, VEX_OP | AUTO_REXW | PREF_F2, AVX},
		spec{"r*yo", op{0x01, 0x2D}, X, VEX_OP | AUTO_REXW | PREF_F2, AVX},
	},
	"vcvtsd2ss": {
		spec{"yoyomq", op{0x01, 0x5A}, X, VEX_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0x5A}, X, VEX_OP | PREF_F2, AVX},
	},
	"vcvtsi2sd": {
		spec{"yoyov*", op{0x01, 0x2A}, X, VEX_OP | AUTO_REXW | PREF_F2, AVX},
	},
	"vcvtsi2ss": {
		spec{"yoyov*", op{0x01, 0x2A}, X, VEX_OP | AUTO_REXW | PREF_F3, AVX},
	},
	"vcvtss2sd": {
		spec{"yoyomd", op{0x01, 0x5A}, X, VEX_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0x5A}, X, VEX_OP | PREF_F3, AVX},
	},
	"vcvtss2si": {
		spec{"r*md", op{0x01, 0x2D}, X, VEX_OP | AUTO_REXW | PREF_F3, AVX},
		spec{"r*yo", op{0x01, 0x2D}, X, VEX_OP | AUTO_REXW | PREF_F3, AVX},
	},
	"vcvttpd2dq": {
		spec{"yom*", op{0x01, 0xE6}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
		spec{"yoy*", op{0x01, 0xE6}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vcvttps2dq": {
		spec{"y*w*", op{0x01, 0x5B}, X, VEX_OP | AUTO_VEXL | PREF_F3, AVX},
	},
	"vcvttsd2si": {
		spec{"r*mq", op{0x01, 0x2C}, X, VEX_OP | AUTO_REXW | PREF_F2, AVX},
		spec{"r*yo", op{0x01, 0x2C}, X, VEX_OP | AUTO_REXW | PREF_F2, AVX},
	},
	"vcvttss2si": {
		spec{"r*md", op{0x01, 0x2C}, X, VEX_OP | AUTO_REXW | PREF_F3, AVX},
		spec{"r*yo", op{0x01, 0x2C}, X, VEX_OP | AUTO_REXW | PREF_F3, AVX},
	},
	"vdivpd": {
		spec{"y*y*w*", op{0x01, 0x5E}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vdivps": {
		spec{"y*y*w*", op{0x01, 0x5E}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vdivsd": {
		spec{"yoyomq", op{0x01, 0x5E}, X, VEX_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0x5E}, X, VEX_OP | PREF_F2, AVX},
	},
	"vdivss": {
		spec{"yoyomd", op{0x01, 0x5E}, X, VEX_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0x5E}, X, VEX_OP | PREF_F3, AVX},
	},
	"vdppd": {
		spec{"yoyowoib", op{0x03, 0x41}, X, VEX_OP | PREF_66, AVX},
	},
	"vdpps": {
		spec{"y*y*w*ib", op{0x03, 0x40}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX},
	},
	"verr": {
		spec{"m!", op{0x0F, 0x00}, 4, DEFAULT, X64_IMPLICIT},
		spec{"rw", op{0x0F, 0x00}, 4, DEFAULT, X64_IMPLICIT},
	},
	"verw": {
		spec{"m!", op{0x0F, 0x00}, 5, DEFAULT, X64_IMPLICIT},
		spec{"rw", op{0x0F, 0x00}, 5, DEFAULT, X64_IMPLICIT},
	},
	"vextractf128": {
		spec{"woyhib", op{0x03, 0x19}, X, WITH_VEXL | VEX_OP | ENC_MR | PREF_66, AVX},
	},
	"vextracti128": {
		spec{"woyhib", op{0x03, 0x39}, X, WITH_VEXL | VEX_OP | ENC_MR | PREF_66, AVX2},
	},
	"vextractps": {
		spec{"vdyoib", op{0x03, 0x17}, X, VEX_OP | ENC_MR | PREF_66, AVX},
	},
	"vfmadd123pd": {
		spec{"y*y*w*", op{0x02, 0xA8}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmadd123ps": {
		spec{"y*y*w*", op{0x02, 0xA8}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmadd123sd": {
		spec{"yoyomq", op{0x02, 0xA9}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xA9}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfmadd123ss": {
		spec{"yoyomd", op{0x02, 0xA9}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xA9}, X, VEX_OP | PREF_66, FMA},
	},
	"vfmadd132pd": {
		spec{"y*y*w*", op{0x02, 0x98}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmadd132ps": {
		spec{"y*y*w*", op{0x02, 0x98}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmadd132sd": {
		spec{"yoyomq", op{0x02, 0x99}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x99}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfmadd132ss": {
		spec{"yoyomd", op{0x02, 0x99}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x99}, X, VEX_OP | PREF_66, FMA},
	},
	"vfmadd213pd": {
		spec{"y*y*w*", op{0x02, 0xA8}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmadd213ps": {
		spec{"y*y*w*", op{0x02, 0xA8}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmadd213sd": {
		spec{"yoyomq", op{0x02, 0xA9}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xA9}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfmadd213ss": {
		spec{"yoyomd", op{0x02, 0xA9}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xA9}, X, VEX_OP | PREF_66, FMA},
	},
	"vfmadd231pd": {
		spec{"y*y*w*", op{0x02, 0xB8}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmadd231ps": {
		spec{"y*y*w*", op{0x02, 0xB8}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmadd231sd": {
		spec{"yoyomq", op{0x02, 0xB9}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xB9}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfmadd231ss": {
		spec{"yoyomd", op{0x02, 0xB9}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xB9}, X, VEX_OP | PREF_66, FMA},
	},
	"vfmadd312pd": {
		spec{"y*y*w*", op{0x02, 0x98}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmadd312ps": {
		spec{"y*y*w*", op{0x02, 0x98}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmadd312sd": {
		spec{"yoyomq", op{0x02, 0x99}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x99}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfmadd312ss": {
		spec{"yoyomd", op{0x02, 0x99}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x99}, X, VEX_OP | PREF_66, FMA},
	},
	"vfmadd321pd": {
		spec{"y*y*w*", op{0x02, 0xB8}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmadd321ps": {
		spec{"y*y*w*", op{0x02, 0xB8}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmadd321sd": {
		spec{"yoyomq", op{0x02, 0xB9}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xB9}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfmadd321ss": {
		spec{"yoyomd", op{0x02, 0xB9}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xB9}, X, VEX_OP | PREF_66, FMA},
	},
	"vfmaddpd": {
		spec{"y*y*y*w*", op{0x03, 0x69}, X, VEX_OP | AUTO_VEXL | PREF_66, AMD | SSE5},
		spec{"y*y*w*y*", op{0x03, 0x69}, X, VEX_OP | AUTO_VEXL | PREF_66, SSE5 | AMD},
	},
	"vfmaddps": {
		spec{"y*y*y*w*", op{0x03, 0x68}, X, VEX_OP | AUTO_VEXL | PREF_66, AMD | SSE5},
		spec{"y*y*w*y*", op{0x03, 0x68}, X, VEX_OP | AUTO_VEXL | PREF_66, SSE5 | AMD},
	},
	"vfmaddsd": {
		spec{"yoyomqyo", op{0x03, 0x6B}, X, VEX_OP | PREF_66, AMD | SSE5},
		spec{"yoyoyomq", op{0x03, 0x6B}, X, VEX_OP | WITH_REXW | PREF_66, AMD | SSE5},
		spec{"yoyoyoyo", op{0x03, 0x6B}, X, VEX_OP | WITH_REXW | PREF_66, AMD | SSE5},
	},
	"vfmaddss": {
		spec{"yoyomdyo", op{0x03, 0x6A}, X, VEX_OP | PREF_66, SSE5 | AMD},
		spec{"yoyoyomd", op{0x03, 0x6A}, X, VEX_OP | WITH_REXW | PREF_66, SSE5 | AMD},
		spec{"yoyoyoyo", op{0x03, 0x6A}, X, VEX_OP | WITH_REXW | PREF_66, SSE5 | AMD},
	},
	"vfmaddsub123pd": {
		spec{"y*y*w*", op{0x02, 0xA6}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmaddsub123ps": {
		spec{"y*y*w*", op{0x02, 0xA6}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmaddsub132pd": {
		spec{"y*y*w*", op{0x02, 0x96}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmaddsub132ps": {
		spec{"y*y*w*", op{0x02, 0x96}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmaddsub213pd": {
		spec{"y*y*w*", op{0x02, 0xA6}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmaddsub213ps": {
		spec{"y*y*w*", op{0x02, 0xA6}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmaddsub231pd": {
		spec{"y*y*w*", op{0x02, 0xB6}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmaddsub231ps": {
		spec{"y*y*w*", op{0x02, 0xB6}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmaddsub312pd": {
		spec{"y*y*w*", op{0x02, 0x96}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmaddsub312ps": {
		spec{"y*y*w*", op{0x02, 0x96}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmaddsub321pd": {
		spec{"y*y*w*", op{0x02, 0xB6}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmaddsub321ps": {
		spec{"y*y*w*", op{0x02, 0xB6}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmaddsubpd": {
		spec{"y*y*y*w*", op{0x03, 0x5D}, X, VEX_OP | AUTO_VEXL | PREF_66, SSE5 | AMD},
		spec{"y*y*w*y*", op{0x03, 0x5D}, X, VEX_OP | AUTO_VEXL | PREF_66, AMD | SSE5},
	},
	"vfmaddsubps": {
		spec{"y*y*y*w*", op{0x03, 0x5C}, X, VEX_OP | AUTO_VEXL | PREF_66, SSE5 | AMD},
		spec{"y*y*w*y*", op{0x03, 0x5C}, X, VEX_OP | AUTO_VEXL | PREF_66, SSE5 | AMD},
	},
	"vfmsub123pd": {
		spec{"y*y*w*", op{0x02, 0xAA}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsub123ps": {
		spec{"y*y*w*", op{0x02, 0xAA}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsub123sd": {
		spec{"yoyomq", op{0x02, 0xAB}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xAB}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfmsub123ss": {
		spec{"yoyomd", op{0x02, 0xAB}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xAB}, X, VEX_OP | PREF_66, FMA},
	},
	"vfmsub132pd": {
		spec{"y*y*w*", op{0x02, 0x9A}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsub132ps": {
		spec{"y*y*w*", op{0x02, 0x9A}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsub132sd": {
		spec{"yoyomq", op{0x02, 0x9B}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x9B}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfmsub132ss": {
		spec{"yoyomd", op{0x02, 0x9B}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x9B}, X, VEX_OP | PREF_66, FMA},
	},
	"vfmsub213pd": {
		spec{"y*y*w*", op{0x02, 0xAA}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsub213ps": {
		spec{"y*y*w*", op{0x02, 0xAA}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsub213sd": {
		spec{"yoyomq", op{0x02, 0xAB}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xAB}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfmsub213ss": {
		spec{"yoyomd", op{0x02, 0xAB}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xAB}, X, VEX_OP | PREF_66, FMA},
	},
	"vfmsub231pd": {
		spec{"y*y*w*", op{0x02, 0xBA}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsub231ps": {
		spec{"y*y*w*", op{0x02, 0xBA}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsub231sd": {
		spec{"yoyomq", op{0x02, 0xBB}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xBB}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfmsub231ss": {
		spec{"yoyomd", op{0x02, 0xBB}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xBB}, X, VEX_OP | PREF_66, FMA},
	},
	"vfmsub312pd": {
		spec{"y*y*w*", op{0x02, 0x9A}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsub312ps": {
		spec{"y*y*w*", op{0x02, 0x9A}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsub312sd": {
		spec{"yoyomq", op{0x02, 0x9B}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x9B}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfmsub312ss": {
		spec{"yoyomd", op{0x02, 0x9B}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x9B}, X, VEX_OP | PREF_66, FMA},
	},
	"vfmsub321pd": {
		spec{"y*y*w*", op{0x02, 0xBA}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsub321ps": {
		spec{"y*y*w*", op{0x02, 0xBA}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsub321sd": {
		spec{"yoyomq", op{0x02, 0xBB}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xBB}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfmsub321ss": {
		spec{"yoyomd", op{0x02, 0xBB}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xBB}, X, VEX_OP | PREF_66, FMA},
	},
	"vfmsubadd123pd": {
		spec{"y*y*w*", op{0x02, 0xA7}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsubadd123ps": {
		spec{"y*y*w*", op{0x02, 0xA7}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsubadd132pd": {
		spec{"y*y*w*", op{0x02, 0x97}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsubadd132ps": {
		spec{"y*y*w*", op{0x02, 0x97}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsubadd213pd": {
		spec{"y*y*w*", op{0x02, 0xA7}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsubadd213ps": {
		spec{"y*y*w*", op{0x02, 0xA7}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsubadd231pd": {
		spec{"y*y*w*", op{0x02, 0xB7}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsubadd231ps": {
		spec{"y*y*w*", op{0x02, 0xB7}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsubadd312pd": {
		spec{"y*y*w*", op{0x02, 0x97}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsubadd312ps": {
		spec{"y*y*w*", op{0x02, 0x97}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsubadd321pd": {
		spec{"y*y*w*", op{0x02, 0xB7}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsubadd321ps": {
		spec{"y*y*w*", op{0x02, 0xB7}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfmsubaddpd": {
		spec{"y*y*y*w*", op{0x03, 0x5F}, X, VEX_OP | AUTO_VEXL | PREF_66, AMD | SSE5},
		spec{"y*y*w*y*", op{0x03, 0x5F}, X, VEX_OP | AUTO_VEXL | PREF_66, AMD | SSE5},
	},
	"vfmsubaddps": {
		spec{"y*y*y*w*", op{0x03, 0x5E}, X, VEX_OP | AUTO_VEXL | PREF_66, AMD | SSE5},
		spec{"y*y*w*y*", op{0x03, 0x5E}, X, VEX_OP | AUTO_VEXL | PREF_66, AMD | SSE5},
	},
	"vfmsubpd": {
		spec{"y*y*y*w*", op{0x03, 0x6D}, X, VEX_OP | AUTO_VEXL | PREF_66, AMD | SSE5},
		spec{"y*y*w*y*", op{0x03, 0x6D}, X, VEX_OP | AUTO_VEXL | PREF_66, AMD | SSE5},
	},
	"vfmsubps": {
		spec{"y*y*y*w*", op{0x03, 0x6C}, X, VEX_OP | AUTO_VEXL | PREF_66, SSE5 | AMD},
		spec{"y*y*w*y*", op{0x03, 0x6C}, X, VEX_OP | AUTO_VEXL | PREF_66, SSE5 | AMD},
	},
	"vfmsubsd": {
		spec{"yoyomqyo", op{0x03, 0x6F}, X, VEX_OP | PREF_66, AMD | SSE5},
		spec{"yoyoyomq", op{0x03, 0x6F}, X, VEX_OP | WITH_REXW | PREF_66, SSE5 | AMD},
		spec{"yoyoyoyo", op{0x03, 0x6F}, X, VEX_OP | WITH_REXW | PREF_66, SSE5 | AMD},
	},
	"vfmsubss": {
		spec{"yoyomdyo", op{0x03, 0x6E}, X, VEX_OP | PREF_66, AMD | SSE5},
		spec{"yoyoyomd", op{0x03, 0x6E}, X, VEX_OP | WITH_REXW | PREF_66, AMD | SSE5},
		spec{"yoyoyoyo", op{0x03, 0x6E}, X, VEX_OP | WITH_REXW | PREF_66, AMD | SSE5},
	},
	"vfnmadd123pd": {
		spec{"y*y*w*", op{0x02, 0xAC}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmadd123ps": {
		spec{"y*y*w*", op{0x02, 0xAC}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmadd123sd": {
		spec{"yoyomq", op{0x02, 0xAD}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xAD}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfnmadd123ss": {
		spec{"yoyomd", op{0x02, 0xAD}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xAD}, X, VEX_OP | PREF_66, FMA},
	},
	"vfnmadd132pd": {
		spec{"y*y*w*", op{0x02, 0x9C}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmadd132ps": {
		spec{"y*y*w*", op{0x02, 0x9C}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmadd132sd": {
		spec{"yoyomq", op{0x02, 0x9D}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x9D}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfnmadd132ss": {
		spec{"yoyomd", op{0x02, 0x9D}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x9D}, X, VEX_OP | PREF_66, FMA},
	},
	"vfnmadd213pd": {
		spec{"y*y*w*", op{0x02, 0xAC}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmadd213ps": {
		spec{"y*y*w*", op{0x02, 0xAC}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmadd213sd": {
		spec{"yoyomq", op{0x02, 0xAD}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xAD}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfnmadd213ss": {
		spec{"yoyomd", op{0x02, 0xAD}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xAD}, X, VEX_OP | PREF_66, FMA},
	},
	"vfnmadd231pd": {
		spec{"y*y*w*", op{0x02, 0xBC}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmadd231ps": {
		spec{"y*y*w*", op{0x02, 0xBC}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmadd231sd": {
		spec{"yoyomq", op{0x02, 0xBD}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xBD}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfnmadd231ss": {
		spec{"yoyomd", op{0x02, 0xBD}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xBD}, X, VEX_OP | PREF_66, FMA},
	},
	"vfnmadd312pd": {
		spec{"y*y*w*", op{0x02, 0x9C}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmadd312ps": {
		spec{"y*y*w*", op{0x02, 0x9C}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmadd312sd": {
		spec{"yoyomq", op{0x02, 0x9D}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x9D}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfnmadd312ss": {
		spec{"yoyomd", op{0x02, 0x9D}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x9D}, X, VEX_OP | PREF_66, FMA},
	},
	"vfnmadd321pd": {
		spec{"y*y*w*", op{0x02, 0xBC}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmadd321ps": {
		spec{"y*y*w*", op{0x02, 0xBC}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmadd321sd": {
		spec{"yoyomq", op{0x02, 0xBD}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xBD}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfnmadd321ss": {
		spec{"yoyomd", op{0x02, 0xBD}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xBD}, X, VEX_OP | PREF_66, FMA},
	},
	"vfnmaddpd": {
		spec{"y*y*y*w*", op{0x03, 0x79}, X, VEX_OP | AUTO_VEXL | PREF_66, SSE5 | AMD},
		spec{"y*y*w*y*", op{0x03, 0x79}, X, VEX_OP | AUTO_VEXL | PREF_66, AMD | SSE5},
	},
	"vfnmaddps": {
		spec{"y*y*y*w*", op{0x03, 0x78}, X, VEX_OP | AUTO_VEXL | PREF_66, AMD | SSE5},
		spec{"y*y*w*y*", op{0x03, 0x78}, X, VEX_OP | AUTO_VEXL | PREF_66, SSE5 | AMD},
	},
	"vfnmaddsd": {
		spec{"yoyomqyo", op{0x03, 0x7B}, X, VEX_OP | PREF_66, SSE5 | AMD},
		spec{"yoyoyomq", op{0x03, 0x7B}, X, VEX_OP | WITH_REXW | PREF_66, AMD | SSE5},
		spec{"yoyoyoyo", op{0x03, 0x7B}, X, VEX_OP | WITH_REXW | PREF_66, AMD | SSE5},
	},
	"vfnmaddss": {
		spec{"yoyomdyo", op{0x03, 0x7A}, X, VEX_OP | PREF_66, SSE5 | AMD},
		spec{"yoyoyomd", op{0x03, 0x7A}, X, VEX_OP | WITH_REXW | PREF_66, AMD | SSE5},
		spec{"yoyoyoyo", op{0x03, 0x7A}, X, VEX_OP | WITH_REXW | PREF_66, AMD | SSE5},
	},
	"vfnmsub123pd": {
		spec{"y*y*w*", op{0x02, 0xAE}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmsub123ps": {
		spec{"y*y*w*", op{0x02, 0xAE}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmsub123sd": {
		spec{"yoyomq", op{0x02, 0xAF}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xAF}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfnmsub123ss": {
		spec{"yoyomd", op{0x02, 0xAF}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xAF}, X, VEX_OP | PREF_66, FMA},
	},
	"vfnmsub132pd": {
		spec{"y*y*w*", op{0x02, 0x9E}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmsub132ps": {
		spec{"y*y*w*", op{0x02, 0x9E}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmsub132sd": {
		spec{"yoyomq", op{0x02, 0x9F}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x9F}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfnmsub132ss": {
		spec{"yoyomd", op{0x02, 0x9F}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x9F}, X, VEX_OP | PREF_66, FMA},
	},
	"vfnmsub213pd": {
		spec{"y*y*w*", op{0x02, 0xAE}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmsub213ps": {
		spec{"y*y*w*", op{0x02, 0xAE}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmsub213sd": {
		spec{"yoyomq", op{0x02, 0xAF}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xAF}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfnmsub213ss": {
		spec{"yoyomd", op{0x02, 0xAF}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xAF}, X, VEX_OP | PREF_66, FMA},
	},
	"vfnmsub231pd": {
		spec{"y*y*w*", op{0x02, 0xBE}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmsub231ps": {
		spec{"y*y*w*", op{0x02, 0xBE}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmsub231sd": {
		spec{"yoyomq", op{0x02, 0xBF}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xBF}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfnmsub231ss": {
		spec{"yoyomd", op{0x02, 0xBF}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xBF}, X, VEX_OP | PREF_66, FMA},
	},
	"vfnmsub312pd": {
		spec{"y*y*w*", op{0x02, 0x9E}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmsub312ps": {
		spec{"y*y*w*", op{0x02, 0x9E}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmsub312sd": {
		spec{"yoyomq", op{0x02, 0x9F}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x9F}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfnmsub312ss": {
		spec{"yoyomd", op{0x02, 0x9F}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0x9F}, X, VEX_OP | PREF_66, FMA},
	},
	"vfnmsub321pd": {
		spec{"y*y*w*", op{0x02, 0xBE}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmsub321ps": {
		spec{"y*y*w*", op{0x02, 0xBE}, X, VEX_OP | AUTO_VEXL | PREF_66, FMA},
	},
	"vfnmsub321sd": {
		spec{"yoyomq", op{0x02, 0xBF}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xBF}, X, VEX_OP | WITH_REXW | PREF_66, FMA},
	},
	"vfnmsub321ss": {
		spec{"yoyomd", op{0x02, 0xBF}, X, VEX_OP | PREF_66, FMA},
		spec{"yoyoyo", op{0x02, 0xBF}, X, VEX_OP | PREF_66, FMA},
	},
	"vfnmsubpd": {
		spec{"y*y*y*w*", op{0x03, 0x7D}, X, VEX_OP | AUTO_VEXL | PREF_66, AMD | SSE5},
		spec{"y*y*w*y*", op{0x03, 0x7D}, X, VEX_OP | AUTO_VEXL | PREF_66, AMD | SSE5},
	},
	"vfnmsubps": {
		spec{"y*y*y*w*", op{0x03, 0x7C}, X, VEX_OP | AUTO_VEXL | PREF_66, SSE5 | AMD},
		spec{"y*y*w*y*", op{0x03, 0x7C}, X, VEX_OP | AUTO_VEXL | PREF_66, AMD | SSE5},
	},
	"vfnmsubsd": {
		spec{"yoyomqyo", op{0x03, 0x7F}, X, VEX_OP | PREF_66, SSE5 | AMD},
		spec{"yoyoyomq", op{0x03, 0x7F}, X, VEX_OP | WITH_REXW | PREF_66, AMD | SSE5},
		spec{"yoyoyoyo", op{0x03, 0x7F}, X, VEX_OP | WITH_REXW | PREF_66, AMD | SSE5},
	},
	"vfnmsubss": {
		spec{"yoyomdyo", op{0x03, 0x7E}, X, VEX_OP | PREF_66, SSE5 | AMD},
		spec{"yoyoyomd", op{0x03, 0x7E}, X, VEX_OP | WITH_REXW | PREF_66, SSE5 | AMD},
		spec{"yoyoyoyo", op{0x03, 0x7E}, X, VEX_OP | WITH_REXW | PREF_66, SSE5 | AMD},
	},
	"vfrczpd": {
		spec{"y*w*", op{0x09, 0x81}, X, XOP_OP | AUTO_VEXL, SSE5 | AMD},
	},
	"vfrczps": {
		spec{"y*w*", op{0x09, 0x80}, X, XOP_OP | AUTO_VEXL, AMD | SSE5},
	},
	"vfrczsd": {
		spec{"yomq", op{0x09, 0x83}, X, XOP_OP, SSE5 | AMD},
		spec{"yoyo", op{0x09, 0x83}, X, XOP_OP, SSE5 | AMD},
	},
	"vfrczss": {
		spec{"yomd", op{0x09, 0x82}, X, XOP_OP, AMD | SSE5},
		spec{"yoyo", op{0x09, 0x82}, X, XOP_OP, AMD | SSE5},
	},
	"vgatherdpd": {
		spec{"y*loy*", op{0x02, 0x92}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX2},
	},
	"vgatherdps": {
		spec{"y*k*y*", op{0x02, 0x92}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX2},
	},
	"vgatherqpd": {
		spec{"y*l*y*", op{0x02, 0x93}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX2},
	},
	"vgatherqps": {
		spec{"yok*yo", op{0x02, 0x93}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX2},
	},
	"vhaddpd": {
		spec{"y*y*w*", op{0x01, 0x7C}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vhaddps": {
		spec{"y*y*w*", op{0x01, 0x7C}, X, VEX_OP | AUTO_VEXL | PREF_F2, AVX},
	},
	"vhsubpd": {
		spec{"y*y*w*", op{0x01, 0x7D}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vhsubps": {
		spec{"y*y*w*", op{0x01, 0x7D}, X, VEX_OP | AUTO_VEXL | PREF_F2, AVX},
	},
	"vinsertf128": {
		spec{"yhyhwoib", op{0x03, 0x18}, X, WITH_VEXL | VEX_OP | PREF_66, AVX},
	},
	"vinserti128": {
		spec{"yhyhwoib", op{0x03, 0x38}, X, WITH_VEXL | VEX_OP | PREF_66, AVX2},
	},
	"vinsertps": {
		spec{"yoyomdib", op{0x03, 0x21}, X, VEX_OP | PREF_66, AVX},
		spec{"yoyoyoib", op{0x03, 0x21}, X, VEX_OP | PREF_66, AVX},
	},
	"vlddqu": {
		spec{"y*m*", op{0x01, 0xF0}, X, VEX_OP | AUTO_VEXL | PREF_F2, AVX},
	},
	"vldmxcsr": {
		spec{"md", op{0x01, 0xAE}, 2, VEX_OP, AVX},
	},
	"vldqqu": {
		spec{"yhmh", op{0x01, 0xF0}, X, WITH_VEXL | VEX_OP | PREF_F2, AVX},
	},
	"vmaskmovdqu": {
		spec{"yoyo", op{0x01, 0xF7}, X, VEX_OP | PREF_66, AVX},
	},
	"vmaskmovpd": {
		spec{"m*y*y*", op{0x02, 0x2F}, X, VEX_OP | AUTO_VEXL | ENC_VM | PREF_66, AVX},
		spec{"y*y*m*", op{0x02, 0x2D}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vmaskmovps": {
		spec{"m*y*y*", op{0x02, 0x2E}, X, VEX_OP | AUTO_VEXL | ENC_VM | PREF_66, AVX},
		spec{"y*y*m*", op{0x02, 0x2C}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vmaxpd": {
		spec{"y*y*w*", op{0x01, 0x5F}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vmaxps": {
		spec{"y*y*w*", op{0x01, 0x5F}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vmaxsd": {
		spec{"yoyomq", op{0x01, 0x5F}, X, VEX_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0x5F}, X, VEX_OP | PREF_F2, AVX},
	},
	"vmaxss": {
		spec{"yoyomd", op{0x01, 0x5F}, X, VEX_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0x5F}, X, VEX_OP | PREF_F3, AVX},
	},
	"vmcall": {
		spec{"", op{0x0F, 0x01, 0xC1}, X, DEFAULT, VMX},
	},
	"vmclear": {
		spec{"m!", op{0x0F, 0xC7}, 6, PREF_66, VMX},
	},
	"vmfunc": {
		spec{"", op{0x0F, 0x01, 0xD4}, X, DEFAULT, VMX},
	},
	"vminpd": {
		spec{"y*y*w*", op{0x01, 0x5D}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vminps": {
		spec{"y*y*w*", op{0x01, 0x5D}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vminsd": {
		spec{"yoyomq", op{0x01, 0x5D}, X, VEX_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0x5D}, X, VEX_OP | PREF_F2, AVX},
	},
	"vminss": {
		spec{"yoyomd", op{0x01, 0x5D}, X, VEX_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0x5D}, X, VEX_OP | PREF_F3, AVX},
	},
	"vmlaunch": {
		spec{"", op{0x0F, 0x01, 0xC2}, X, DEFAULT, VMX},
	},
	"vmload": {
		spec{"", op{0x0F, 0x01, 0xDA}, X, DEFAULT, AMD | VMX},
	},
	"vmmcall": {
		spec{"", op{0x0F, 0x01, 0xD9}, X, DEFAULT, AMD | VMX},
	},
	"vmovapd": {
		spec{"y*w*", op{0x01, 0x28}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
		spec{"whyh", op{0x01, 0x29}, X, VEX_OP | WITH_VEXL | ENC_MR | PREF_66, AVX},
		spec{"woyo", op{0x01, 0x29}, X, VEX_OP | ENC_MR | PREF_66, AVX},
	},
	"vmovaps": {
		spec{"y*w*", op{0x01, 0x28}, X, VEX_OP | AUTO_VEXL, AVX},
		spec{"whyh", op{0x01, 0x29}, X, VEX_OP | WITH_VEXL | ENC_MR, AVX},
		spec{"woyo", op{0x01, 0x29}, X, VEX_OP | ENC_MR, AVX},
	},
	"vmovd": {
		spec{"yovd", op{0x01, 0x6E}, X, VEX_OP | PREF_66, AVX},
		spec{"vdyo", op{0x01, 0x7E}, X, VEX_OP | ENC_MR | PREF_66, AVX},
	},
	"vmovddup": {
		spec{"y*w*", op{0x01, 0x12}, X, VEX_OP | AUTO_VEXL | PREF_F2, AVX},
		spec{"yomq", op{0x01, 0x12}, X, VEX_OP | PREF_F2, AVX},
	},
	"vmovdqa": {
		spec{"y*w*", op{0x01, 0x6F}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
		spec{"whyh", op{0x01, 0x7F}, X, VEX_OP | WITH_VEXL | ENC_MR | PREF_66, AVX},
		spec{"woyo", op{0x01, 0x7F}, X, VEX_OP | ENC_MR | PREF_66, AVX},
	},
	"vmovdqu": {
		spec{"y*w*", op{0x01, 0x6F}, X, VEX_OP | AUTO_VEXL | PREF_F3, AVX},
		spec{"whyh", op{0x01, 0x7F}, X, VEX_OP | WITH_VEXL | ENC_MR | PREF_F3, AVX},
		spec{"woyo", op{0x01, 0x7F}, X, VEX_OP | ENC_MR | PREF_F3, AVX},
	},
	"vmovhlps": {
		spec{"yoyoyo", op{0x01, 0x12}, X, VEX_OP, AVX},
	},
	"vmovhpd": {
		spec{"mqyo", op{0x01, 0x17}, X, VEX_OP | ENC_MR | PREF_66, AVX},
		spec{"yoyomq", op{0x01, 0x16}, X, VEX_OP | PREF_66, AVX},
	},
	"vmovhps": {
		spec{"mqyo", op{0x01, 0x17}, X, VEX_OP | ENC_MR, AVX},
		spec{"yoyomq", op{0x01, 0x16}, X, VEX_OP, AVX},
	},
	"vmovlhps": {
		spec{"yoyoyo", op{0x01, 0x16}, X, VEX_OP, AVX},
	},
	"vmovlpd": {
		spec{"mqyo", op{0x01, 0x13}, X, VEX_OP | ENC_MR | PREF_66, AVX},
		spec{"yoyomq", op{0x01, 0x12}, X, VEX_OP | PREF_66, AVX},
	},
	"vmovlps": {
		spec{"mqyo", op{0x01, 0x13}, X, VEX_OP | ENC_MR, AVX},
		spec{"yoyomq", op{0x01, 0x12}, X, VEX_OP, AVX},
	},
	"vmovmskpd": {
		spec{"r*y*", op{0x01, 0x50}, X, VEX_OP | PREF_66, AVX},
	},
	"vmovmskps": {
		spec{"r*y*", op{0x01, 0x50}, X, VEX_OP, AVX},
	},
	"vmovntdq": {
		spec{"m*y*", op{0x01, 0xE7}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX},
	},
	"vmovntdqa": {
		spec{"y*m*", op{0x02, 0x2A}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vmovntpd": {
		spec{"m*y*", op{0x01, 0x2B}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX},
	},
	"vmovntps": {
		spec{"m*y*", op{0x01, 0x2B}, X, VEX_OP | AUTO_VEXL | ENC_MR, AVX},
	},
	"vmovntqq": {
		spec{"mhyh", op{0x01, 0xE7}, X, WITH_VEXL | VEX_OP | ENC_MR | PREF_66, AVX},
	},
	"vmovq": {
		spec{"mqyo", op{0x01, 0xD6}, X, VEX_OP | ENC_MR | PREF_66, AVX},
		spec{"yomq", op{0x01, 0x7E}, X, VEX_OP | PREF_F3, AVX},
		spec{"yovq", op{0x01, 0x6E}, X, WITH_REXW | VEX_OP | PREF_66, AVX},
		spec{"yoyo", op{0x01, 0x7E}, X, VEX_OP | PREF_F3, AVX},
		spec{"yoyo", op{0x01, 0xD6}, X, VEX_OP | ENC_MR | PREF_66, AVX},
		spec{"vqyo", op{0x01, 0x7E}, X, WITH_REXW | VEX_OP | ENC_MR | PREF_66, AVX},
	},
	"vmovqqa": {
		spec{"yhwh", op{0x01, 0x6F}, X, WITH_VEXL | VEX_OP | PREF_66, AVX},
		spec{"whyh", op{0x01, 0x7F}, X, WITH_VEXL | VEX_OP | ENC_MR | PREF_66, AVX},
	},
	"vmovqqu": {
		spec{"yhwh", op{0x01, 0x6F}, X, WITH_VEXL | VEX_OP | PREF_F3, AVX},
		spec{"whyh", op{0x01, 0x7F}, X, WITH_VEXL | VEX_OP | ENC_MR | PREF_F3, AVX},
	},
	"vmovsd": {
		spec{"mqyo", op{0x01, 0x11}, X, VEX_OP | ENC_MR | PREF_F2, AVX},
		spec{"yomq", op{0x01, 0x10}, X, VEX_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0x10}, X, VEX_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0x11}, X, VEX_OP | ENC_VM | PREF_F2, AVX},
	},
	"vmovshdup": {
		spec{"y*w*", op{0x01, 0x16}, X, VEX_OP | AUTO_VEXL | PREF_F3, AVX},
	},
	"vmovsldup": {
		spec{"y*w*", op{0x01, 0x12}, X, VEX_OP | AUTO_VEXL | PREF_F3, AVX},
	},
	"vmovss": {
		spec{"mdyo", op{0x01, 0x11}, X, VEX_OP | ENC_MR | PREF_F3, AVX},
		spec{"yomd", op{0x01, 0x10}, X, VEX_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0x10}, X, VEX_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0x11}, X, VEX_OP | ENC_VM | PREF_F3, AVX},
	},
	"vmovupd": {
		spec{"y*w*", op{0x01, 0x10}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
		spec{"whyh", op{0x01, 0x11}, X, VEX_OP | WITH_VEXL | ENC_MR | PREF_66, AVX},
		spec{"woyo", op{0x01, 0x11}, X, VEX_OP | ENC_MR | PREF_66, AVX},
	},
	"vmovups": {
		spec{"y*w*", op{0x01, 0x10}, X, VEX_OP | AUTO_VEXL, AVX},
		spec{"whyh", op{0x01, 0x11}, X, VEX_OP | WITH_VEXL | ENC_MR, AVX},
		spec{"woyo", op{0x01, 0x11}, X, VEX_OP | ENC_MR, AVX},
	},
	"vmpsadbw": {
		spec{"y*y*w*ib", op{0x03, 0x42}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX},
	},
	"vmptrld": {
		spec{"m!", op{0x0F, 0xC7}, 6, DEFAULT, VMX},
	},
	"vmptrst": {
		spec{"m!", op{0x0F, 0xC7}, 7, DEFAULT, VMX},
	},
	"vmread": {
		spec{"vqrq", op{0x0F, 0x78}, X, ENC_MR, VMX},
	},
	"vmresume": {
		spec{"", op{0x0F, 0x01, 0xC3}, X, DEFAULT, VMX},
	},
	"vmrun": {
		spec{"", op{0x0F, 0x01, 0xD8}, X, DEFAULT, AMD | VMX},
	},
	"vmsave": {
		spec{"", op{0x0F, 0x01, 0xDB}, X, DEFAULT, VMX | AMD},
	},
	"vmulpd": {
		spec{"y*y*w*", op{0x01, 0x59}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vmulps": {
		spec{"y*y*w*", op{0x01, 0x59}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vmulsd": {
		spec{"yoyomq", op{0x01, 0x59}, X, VEX_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0x59}, X, VEX_OP | PREF_F2, AVX},
	},
	"vmulss": {
		spec{"yoyomd", op{0x01, 0x59}, X, VEX_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0x59}, X, VEX_OP | PREF_F3, AVX},
	},
	"vmwrite": {
		spec{"rqvq", op{0x0F, 0x79}, X, DEFAULT, VMX},
	},
	"vmxoff": {
		spec{"", op{0x0F, 0x01, 0xC4}, X, DEFAULT, VMX},
	},
	"vmxon": {
		spec{"m!", op{0x0F, 0xC7}, 6, PREF_F3, VMX},
	},
	"vorpd": {
		spec{"y*y*w*", op{0x01, 0x56}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vorps": {
		spec{"y*y*w*", op{0x01, 0x56}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vpabsb": {
		spec{"y*w*", op{0x02, 0x1C}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpabsd": {
		spec{"y*w*", op{0x02, 0x1E}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpabsw": {
		spec{"y*w*", op{0x02, 0x1D}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpackssdw": {
		spec{"y*y*w*", op{0x01, 0x6B}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpacksswb": {
		spec{"y*y*w*", op{0x01, 0x63}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpackusdw": {
		spec{"y*y*w*", op{0x02, 0x2B}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpackuswb": {
		spec{"y*y*w*", op{0x01, 0x67}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpaddb": {
		spec{"y*y*w*", op{0x01, 0xFC}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpaddd": {
		spec{"y*y*w*", op{0x01, 0xFE}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpaddq": {
		spec{"y*y*w*", op{0x01, 0xD4}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpaddsb": {
		spec{"y*y*w*", op{0x01, 0xEC}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpaddsw": {
		spec{"y*y*w*", op{0x01, 0xED}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpaddusb": {
		spec{"y*y*w*", op{0x01, 0xDC}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpaddusw": {
		spec{"y*y*w*", op{0x01, 0xDD}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpaddw": {
		spec{"y*y*w*", op{0x01, 0xFD}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpalignr": {
		spec{"y*y*w*ib", op{0x03, 0x0F}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX},
	},
	"vpand": {
		spec{"y*y*w*", op{0x01, 0xDB}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpandn": {
		spec{"y*y*w*", op{0x01, 0xDF}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpavgb": {
		spec{"y*y*w*", op{0x01, 0xE0}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpavgw": {
		spec{"y*y*w*", op{0x01, 0xE3}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpblendd": {
		spec{"y*y*w*ib", op{0x03, 0x02}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX2},
	},
	"vpblendvb": {
		spec{"y*y*w*y*", op{0x03, 0x4C}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpblendw": {
		spec{"y*y*w*ib", op{0x03, 0x0E}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX},
	},
	"vpbroadcastb": {
		spec{"y*mb", op{0x02, 0x78}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX2},
		spec{"y*yo", op{0x02, 0x78}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX2},
	},
	"vpbroadcastd": {
		spec{"y*md", op{0x02, 0x58}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX2},
		spec{"y*yo", op{0x02, 0x58}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX2},
	},
	"vpbroadcastq": {
		spec{"yhmq", op{0x02, 0x59}, X, VEX_OP | WITH_VEXL | PREF_66, AVX2},
		spec{"yomq", op{0x02, 0x59}, X, VEX_OP | PREF_66, AVX2},
		spec{"y*yo", op{0x02, 0x59}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX2},
	},
	"vpbroadcastw": {
		spec{"y*mw", op{0x02, 0x79}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX2},
		spec{"y*yo", op{0x02, 0x79}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX2},
	},
	"vpclmulhqhqdq": {
		spec{"yoyowo", op{0x03, 0x44, 0x11}, X, VEX_OP | PREF_66 | IMM_OP, AVX},
	},
	"vpclmulhqlqdq": {
		spec{"yoyowo", op{0x03, 0x44, 0x01}, X, VEX_OP | IMM_OP | PREF_66, AVX},
	},
	"vpclmullqhqdq": {
		spec{"yoyowo", op{0x03, 0x44, 0x10}, X, VEX_OP | IMM_OP | PREF_66, AVX},
	},
	"vpclmullqlqdq": {
		spec{"yoyowo", op{0x03, 0x44, 0x00}, X, VEX_OP | IMM_OP | PREF_66, AVX},
	},
	"vpclmulqdq": {
		spec{"yoyowoib", op{0x03, 0x44}, X, VEX_OP | PREF_66, AVX},
	},
	"vpcmov": {
		spec{"y*y*w*y*", op{0x08, 0xA2}, X, XOP_OP | AUTO_VEXL, SSE5 | AMD},
		spec{"y*y*y*w*", op{0x08, 0xA2}, X, XOP_OP | AUTO_VEXL, AMD | SSE5},
	},
	"vpcmpeqb": {
		spec{"y*y*w*", op{0x01, 0x74}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpcmpeqd": {
		spec{"y*y*w*", op{0x01, 0x76}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpcmpeqq": {
		spec{"y*y*w*", op{0x02, 0x29}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpcmpeqw": {
		spec{"y*y*w*", op{0x01, 0x75}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpcmpestri": {
		spec{"yowoib", op{0x03, 0x61}, X, VEX_OP | PREF_66, AVX},
	},
	"vpcmpestrm": {
		spec{"yowoib", op{0x03, 0x60}, X, VEX_OP | PREF_66, AVX},
	},
	"vpcmpgtb": {
		spec{"y*y*w*", op{0x01, 0x64}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpcmpgtd": {
		spec{"y*y*w*", op{0x01, 0x66}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpcmpgtq": {
		spec{"y*y*w*", op{0x02, 0x37}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpcmpgtw": {
		spec{"y*y*w*", op{0x01, 0x65}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpcmpistri": {
		spec{"yowoib", op{0x03, 0x63}, X, VEX_OP | PREF_66, AVX},
	},
	"vpcmpistrm": {
		spec{"yowoib", op{0x03, 0x62}, X, VEX_OP | PREF_66, AVX},
	},
	"vpcomb": {
		spec{"yoyowoib", op{0x08, 0xCC}, X, XOP_OP, AMD | SSE5},
	},
	"vpcomd": {
		spec{"yoyowoib", op{0x08, 0xCE}, X, XOP_OP, AMD | SSE5},
	},
	"vpcomq": {
		spec{"yoyowoib", op{0x08, 0xCF}, X, XOP_OP, SSE5 | AMD},
	},
	"vpcomub": {
		spec{"yoyowoib", op{0x08, 0xEC}, X, XOP_OP, AMD | SSE5},
	},
	"vpcomud": {
		spec{"yoyowoib", op{0x08, 0xEE}, X, XOP_OP, SSE5 | AMD},
	},
	"vpcomuq": {
		spec{"yoyowoib", op{0x08, 0xEF}, X, XOP_OP, AMD | SSE5},
	},
	"vpcomuw": {
		spec{"yoyowoib", op{0x08, 0xED}, X, XOP_OP, SSE5 | AMD},
	},
	"vpcomw": {
		spec{"yoyowoib", op{0x08, 0xCD}, X, XOP_OP, AMD | SSE5},
	},
	"vperm2f128": {
		spec{"yhyhwhib", op{0x03, 0x06}, X, WITH_VEXL | VEX_OP | PREF_66, AVX},
	},
	"vperm2i128": {
		spec{"yhyhwhib", op{0x03, 0x46}, X, WITH_VEXL | VEX_OP | PREF_66, AVX2},
	},
	"vpermd": {
		spec{"yhyhwh", op{0x02, 0x36}, X, WITH_VEXL | VEX_OP | PREF_66, AVX2},
	},
	"vpermilpd": {
		spec{"y*y*w*", op{0x02, 0x0D}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
		spec{"y*w*ib", op{0x03, 0x05}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpermilps": {
		spec{"y*y*w*", op{0x02, 0x0C}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
		spec{"y*w*ib", op{0x03, 0x04}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpermpd": {
		spec{"yhwhib", op{0x03, 0x01}, X, WITH_VEXL | WITH_REXW | VEX_OP | PREF_66, AVX2},
	},
	"vpermps": {
		spec{"yhyhwh", op{0x02, 0x16}, X, WITH_VEXL | VEX_OP | PREF_66, AVX2},
	},
	"vpermq": {
		spec{"yhwhib", op{0x03, 0x00}, X, WITH_VEXL | WITH_REXW | VEX_OP | PREF_66, AVX2},
	},
	"vpextrb": {
		spec{"mbyoib", op{0x03, 0x14}, X, VEX_OP | ENC_MR | PREF_66, AVX},
		spec{"rdyoib", op{0x03, 0x14}, X, VEX_OP | ENC_MR | PREF_66, AVX},
		spec{"rqyoib", op{0x03, 0x14}, X, VEX_OP | ENC_MR | PREF_66, AVX},
	},
	"vpextrd": {
		spec{"rqyoib", op{0x03, 0x16}, X, VEX_OP | ENC_MR | PREF_66, AVX},
		spec{"vdyoib", op{0x03, 0x16}, X, VEX_OP | ENC_MR | PREF_66, AVX},
	},
	"vpextrq": {
		spec{"vqyoib", op{0x03, 0x16}, X, WITH_REXW | VEX_OP | ENC_MR | PREF_66, AVX},
	},
	"vpextrw": {
		spec{"mwyoib", op{0x03, 0x15}, X, VEX_OP | ENC_MR | PREF_66, AVX},
		spec{"rdyoib", op{0x01, 0xC5}, X, VEX_OP | PREF_66, AVX},
		spec{"rdyoib", op{0x03, 0x15}, X, VEX_OP | ENC_MR | PREF_66, AVX},
		spec{"rqyoib", op{0x01, 0xC5}, X, VEX_OP | PREF_66, AVX},
		spec{"rqyoib", op{0x03, 0x15}, X, VEX_OP | ENC_MR | PREF_66, AVX},
	},
	"vpgatherdd": {
		spec{"y*k*y*", op{0x02, 0x90}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX2},
	},
	"vpgatherdq": {
		spec{"y*loy*", op{0x02, 0x90}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX2},
	},
	"vpgatherqd": {
		spec{"yok*yo", op{0x02, 0x91}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX2},
	},
	"vpgatherqq": {
		spec{"y*l*y*", op{0x02, 0x91}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX2},
	},
	"vphaddbd": {
		spec{"yowo", op{0x09, 0xC2}, X, XOP_OP, SSE5 | AMD},
	},
	"vphaddbq": {
		spec{"yowo", op{0x09, 0xC3}, X, XOP_OP, SSE5 | AMD},
	},
	"vphaddbw": {
		spec{"yowo", op{0x09, 0xC1}, X, XOP_OP, SSE5 | AMD},
	},
	"vphaddd": {
		spec{"y*y*w*", op{0x02, 0x02}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vphadddq": {
		spec{"yowo", op{0x09, 0xCB}, X, XOP_OP, SSE5 | AMD},
	},
	"vphaddsw": {
		spec{"y*y*w*", op{0x02, 0x03}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vphaddubd": {
		spec{"yowo", op{0x09, 0xD2}, X, XOP_OP, SSE5 | AMD},
	},
	"vphaddubq": {
		spec{"yowo", op{0x09, 0xD3}, X, XOP_OP, AMD | SSE5},
	},
	"vphaddubw": {
		spec{"yowo", op{0x09, 0xD1}, X, XOP_OP, SSE5 | AMD},
	},
	"vphaddudq": {
		spec{"yowo", op{0x09, 0xDB}, X, XOP_OP, AMD | SSE5},
	},
	"vphadduwd": {
		spec{"yowo", op{0x09, 0xD6}, X, XOP_OP, AMD | SSE5},
	},
	"vphadduwq": {
		spec{"yowo", op{0x09, 0xD7}, X, XOP_OP, AMD | SSE5},
	},
	"vphaddw": {
		spec{"y*y*w*", op{0x02, 0x01}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vphaddwd": {
		spec{"yowo", op{0x09, 0xC6}, X, XOP_OP, AMD | SSE5},
	},
	"vphaddwq": {
		spec{"yowo", op{0x09, 0xC7}, X, XOP_OP, AMD | SSE5},
	},
	"vphminposuw": {
		spec{"yowo", op{0x02, 0x41}, X, VEX_OP | PREF_66, AVX},
	},
	"vphsubbw": {
		spec{"yowo", op{0x09, 0xE1}, X, XOP_OP, SSE5 | AMD},
	},
	"vphsubd": {
		spec{"y*y*w*", op{0x02, 0x06}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vphsubdq": {
		spec{"yowo", op{0x09, 0xE3}, X, XOP_OP, SSE5 | AMD},
	},
	"vphsubsw": {
		spec{"y*y*w*", op{0x02, 0x07}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vphsubw": {
		spec{"y*y*w*", op{0x02, 0x05}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vphsubwd": {
		spec{"yowo", op{0x09, 0xE2}, X, XOP_OP, SSE5 | AMD},
	},
	"vpinsrb": {
		spec{"yoyordib", op{0x03, 0x20}, X, VEX_OP | PREF_66, AVX},
		spec{"yoyovbib", op{0x03, 0x20}, X, VEX_OP | PREF_66, AVX},
	},
	"vpinsrd": {
		spec{"yoyovdib", op{0x03, 0x22}, X, VEX_OP | PREF_66, AVX},
	},
	"vpinsrq": {
		spec{"yoyovqib", op{0x03, 0x22}, X, VEX_OP | WITH_REXW | PREF_66, AVX},
	},
	"vpinsrw": {
		spec{"yoyordib", op{0x01, 0xC4}, X, VEX_OP | PREF_66, AVX},
		spec{"yoyovwib", op{0x01, 0xC4}, X, VEX_OP | PREF_66, AVX},
	},
	"vpmacsdd": {
		spec{"yoyowoyo", op{0x08, 0x9E}, X, XOP_OP, AMD | SSE5},
	},
	"vpmacsdqh": {
		spec{"yoyowoyo", op{0x08, 0x9F}, X, XOP_OP, SSE5 | AMD},
	},
	"vpmacsdql": {
		spec{"yoyowoyo", op{0x08, 0x97}, X, XOP_OP, AMD | SSE5},
	},
	"vpmacssdd": {
		spec{"yoyowoyo", op{0x08, 0x8E}, X, XOP_OP, SSE5 | AMD},
	},
	"vpmacssdqh": {
		spec{"yoyowoyo", op{0x08, 0x8F}, X, XOP_OP, AMD | SSE5},
	},
	"vpmacssdql": {
		spec{"yoyowoyo", op{0x08, 0x87}, X, XOP_OP, SSE5 | AMD},
	},
	"vpmacsswd": {
		spec{"yoyowoyo", op{0x08, 0x86}, X, XOP_OP, AMD | SSE5},
	},
	"vpmacssww": {
		spec{"yoyowoyo", op{0x08, 0x85}, X, XOP_OP, AMD | SSE5},
	},
	"vpmacswd": {
		spec{"yoyowoyo", op{0x08, 0x96}, X, XOP_OP, SSE5 | AMD},
	},
	"vpmacsww": {
		spec{"yoyowoyo", op{0x08, 0x95}, X, XOP_OP, AMD | SSE5},
	},
	"vpmadcsswd": {
		spec{"yoyowoyo", op{0x08, 0xA6}, X, XOP_OP, SSE5 | AMD},
	},
	"vpmadcswd": {
		spec{"yoyowoyo", op{0x08, 0xB6}, X, XOP_OP, AMD | SSE5},
	},
	"vpmaddubsw": {
		spec{"y*y*w*", op{0x02, 0x04}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmaddwd": {
		spec{"y*y*w*", op{0x01, 0xF5}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmaskmovd": {
		spec{"m*y*y*", op{0x02, 0x8E}, X, VEX_OP | AUTO_VEXL | ENC_VM | PREF_66, AVX2},
		spec{"y*y*m*", op{0x02, 0x8C}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX2},
	},
	"vpmaskmovq": {
		spec{"m*y*y*", op{0x02, 0x8E}, X, VEX_OP | AUTO_VEXL | ENC_VM | PREF_66, AVX2},
		spec{"y*y*m*", op{0x02, 0x8C}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX2},
	},
	"vpmaxsb": {
		spec{"y*y*w*", op{0x02, 0x3C}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmaxsd": {
		spec{"y*y*w*", op{0x02, 0x3D}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmaxsw": {
		spec{"y*y*w*", op{0x01, 0xEE}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmaxub": {
		spec{"y*y*w*", op{0x01, 0xDE}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmaxud": {
		spec{"y*y*w*", op{0x02, 0x3F}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmaxuw": {
		spec{"y*y*w*", op{0x02, 0x3E}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpminsb": {
		spec{"y*y*w*", op{0x02, 0x38}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpminsd": {
		spec{"y*y*w*", op{0x02, 0x39}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpminsw": {
		spec{"y*y*w*", op{0x01, 0xEA}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpminub": {
		spec{"y*y*w*", op{0x01, 0xDA}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpminud": {
		spec{"y*y*w*", op{0x02, 0x3B}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpminuw": {
		spec{"y*y*w*", op{0x02, 0x3A}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmovmskb": {
		spec{"r*y*", op{0x01, 0xD7}, X, VEX_OP | PREF_66, AVX},
	},
	"vpmovsxbd": {
		spec{"yomd", op{0x02, 0x21}, X, VEX_OP | PREF_66, AVX},
		spec{"y*yo", op{0x02, 0x21}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmovsxbq": {
		spec{"y*mw", op{0x02, 0x22}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
		spec{"y*yo", op{0x02, 0x22}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmovsxbw": {
		spec{"yomq", op{0x02, 0x20}, X, VEX_OP | PREF_66, AVX},
		spec{"y*wo", op{0x02, 0x20}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmovsxdq": {
		spec{"yomq", op{0x02, 0x25}, X, VEX_OP | PREF_66, AVX},
		spec{"y*wo", op{0x02, 0x25}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmovsxwd": {
		spec{"yomq", op{0x02, 0x23}, X, VEX_OP | PREF_66, AVX},
		spec{"y*wo", op{0x02, 0x23}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmovsxwq": {
		spec{"yomd", op{0x02, 0x24}, X, VEX_OP | PREF_66, AVX},
		spec{"y*yo", op{0x02, 0x24}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmovzxbd": {
		spec{"yomd", op{0x02, 0x31}, X, VEX_OP | PREF_66, AVX},
		spec{"y*yo", op{0x02, 0x31}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmovzxbq": {
		spec{"y*mw", op{0x02, 0x32}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
		spec{"y*yo", op{0x02, 0x32}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmovzxbw": {
		spec{"yomq", op{0x02, 0x30}, X, VEX_OP | PREF_66, AVX},
		spec{"y*wo", op{0x02, 0x30}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmovzxdq": {
		spec{"yomq", op{0x02, 0x35}, X, VEX_OP | PREF_66, AVX},
		spec{"y*wo", op{0x02, 0x35}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmovzxwd": {
		spec{"yomq", op{0x02, 0x33}, X, VEX_OP | PREF_66, AVX},
		spec{"y*wo", op{0x02, 0x33}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmovzxwq": {
		spec{"yomd", op{0x02, 0x34}, X, VEX_OP | PREF_66, AVX},
		spec{"y*yo", op{0x02, 0x34}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmuldq": {
		spec{"y*y*w*", op{0x02, 0x28}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmulhrsw": {
		spec{"y*y*w*", op{0x02, 0x0B}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmulhuw": {
		spec{"y*y*w*", op{0x01, 0xE4}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmulhw": {
		spec{"y*y*w*", op{0x01, 0xE5}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmulld": {
		spec{"y*y*w*", op{0x02, 0x40}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmullw": {
		spec{"y*y*w*", op{0x01, 0xD5}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpmuludq": {
		spec{"y*y*w*", op{0x01, 0xF4}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpor": {
		spec{"y*y*w*", op{0x01, 0xEB}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpperm": {
		spec{"yoyowoyo", op{0x08, 0xA3}, X, XOP_OP, AMD | SSE5},
		spec{"yoyoyowo", op{0x08, 0xA3}, X, WITH_REXW | XOP_OP, SSE5 | AMD},
	},
	"vprotb": {
		spec{"yowoib", op{0x08, 0xC0}, X, XOP_OP, SSE5 | AMD},
		spec{"yowoyo", op{0x09, 0x90}, X, XOP_OP | ENC_MR, AMD | SSE5},
		spec{"yoyowo", op{0x09, 0x90}, X, WITH_REXW | XOP_OP, SSE5 | AMD},
	},
	"vprotd": {
		spec{"yowoib", op{0x08, 0xC2}, X, XOP_OP, AMD | SSE5},
		spec{"yowoyo", op{0x09, 0x92}, X, XOP_OP | ENC_MR, AMD | SSE5},
		spec{"yoyowo", op{0x09, 0x92}, X, WITH_REXW | XOP_OP, SSE5 | AMD},
	},
	"vprotq": {
		spec{"yowoib", op{0x08, 0xC3}, X, XOP_OP, AMD | SSE5},
		spec{"yowoyo", op{0x09, 0x93}, X, XOP_OP | ENC_MR, AMD | SSE5},
		spec{"yoyowo", op{0x09, 0x93}, X, WITH_REXW | XOP_OP, SSE5 | AMD},
	},
	"vprotw": {
		spec{"yowoib", op{0x08, 0xC1}, X, XOP_OP, AMD | SSE5},
		spec{"yowoyo", op{0x09, 0x91}, X, XOP_OP | ENC_MR, SSE5 | AMD},
		spec{"yoyowo", op{0x09, 0x91}, X, WITH_REXW | XOP_OP, AMD | SSE5},
	},
	"vpsadbw": {
		spec{"y*y*w*", op{0x01, 0xF6}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpshab": {
		spec{"yowoyo", op{0x09, 0x98}, X, XOP_OP | ENC_MR, AMD | SSE5},
		spec{"yoyowo", op{0x09, 0x98}, X, WITH_REXW | XOP_OP, SSE5 | AMD},
	},
	"vpshad": {
		spec{"yowoyo", op{0x09, 0x9A}, X, XOP_OP | ENC_MR, SSE5 | AMD},
		spec{"yoyowo", op{0x09, 0x9A}, X, WITH_REXW | XOP_OP, AMD | SSE5},
	},
	"vpshaq": {
		spec{"yowoyo", op{0x09, 0x9B}, X, XOP_OP | ENC_MR, SSE5 | AMD},
		spec{"yoyowo", op{0x09, 0x9B}, X, WITH_REXW | XOP_OP, SSE5 | AMD},
	},
	"vpshaw": {
		spec{"yowoyo", op{0x09, 0x99}, X, XOP_OP | ENC_MR, AMD | SSE5},
		spec{"yoyowo", op{0x09, 0x99}, X, WITH_REXW | XOP_OP, SSE5 | AMD},
	},
	"vpshlb": {
		spec{"yowoyo", op{0x09, 0x94}, X, XOP_OP | ENC_MR, AMD | SSE5},
		spec{"yoyowo", op{0x09, 0x94}, X, WITH_REXW | XOP_OP, AMD | SSE5},
	},
	"vpshld": {
		spec{"yowoyo", op{0x09, 0x96}, X, XOP_OP | ENC_MR, SSE5 | AMD},
		spec{"yoyowo", op{0x09, 0x96}, X, WITH_REXW | XOP_OP, SSE5 | AMD},
	},
	"vpshlq": {
		spec{"yowoyo", op{0x09, 0x97}, X, XOP_OP | ENC_MR, AMD | SSE5},
		spec{"yoyowo", op{0x09, 0x97}, X, WITH_REXW | XOP_OP, AMD | SSE5},
	},
	"vpshlw": {
		spec{"yowoyo", op{0x09, 0x95}, X, XOP_OP | ENC_MR, AMD | SSE5},
		spec{"yoyowo", op{0x09, 0x95}, X, WITH_REXW | XOP_OP, SSE5 | AMD},
	},
	"vpshufb": {
		spec{"y*y*w*", op{0x02, 0x00}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpshufd": {
		spec{"y*w*ib", op{0x01, 0x70}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpshufhw": {
		spec{"y*w*ib", op{0x01, 0x70}, X, VEX_OP | AUTO_VEXL | PREF_F3, AVX},
	},
	"vpshuflw": {
		spec{"y*w*ib", op{0x01, 0x70}, X, VEX_OP | AUTO_VEXL | PREF_F2, AVX},
	},
	"vpsignb": {
		spec{"y*y*w*", op{0x02, 0x08}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsignd": {
		spec{"y*y*w*", op{0x02, 0x0A}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsignw": {
		spec{"y*y*w*", op{0x02, 0x09}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpslld": {
		spec{"y*y*ib", op{0x01, 0x72}, 6, VEX_OP | AUTO_VEXL | ENC_VM | PREF_66, AVX},
		spec{"y*y*wo", op{0x01, 0xF2}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpslldq": {
		spec{"y*y*ib", op{0x01, 0x73}, 7, VEX_OP | AUTO_VEXL | ENC_VM | PREF_66, AVX},
	},
	"vpsllq": {
		spec{"y*y*ib", op{0x01, 0x73}, 6, VEX_OP | AUTO_VEXL | ENC_VM | PREF_66, AVX},
		spec{"y*y*wo", op{0x01, 0xF3}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsllvd": {
		spec{"y*y*w*", op{0x02, 0x47}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX2},
	},
	"vpsllvq": {
		spec{"y*y*w*", op{0x02, 0x47}, X, VEX_OP | AUTO_VEXL | WITH_REXW | PREF_66, AVX2},
	},
	"vpsllw": {
		spec{"y*y*ib", op{0x01, 0x71}, 6, VEX_OP | AUTO_VEXL | ENC_VM | PREF_66, AVX},
		spec{"y*y*wo", op{0x01, 0xF1}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsrad": {
		spec{"y*y*ib", op{0x01, 0x72}, 4, VEX_OP | AUTO_VEXL | ENC_VM | PREF_66, AVX},
		spec{"y*y*wo", op{0x01, 0xE2}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsravd": {
		spec{"y*y*w*", op{0x02, 0x46}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX2},
	},
	"vpsraw": {
		spec{"y*y*ib", op{0x01, 0x71}, 4, VEX_OP | AUTO_VEXL | ENC_VM | PREF_66, AVX},
		spec{"y*y*wo", op{0x01, 0xE1}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsrld": {
		spec{"y*y*ib", op{0x01, 0x72}, 2, VEX_OP | AUTO_VEXL | ENC_VM | PREF_66, AVX},
		spec{"y*y*wo", op{0x01, 0xD2}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsrldq": {
		spec{"y*y*ib", op{0x01, 0x73}, 3, VEX_OP | AUTO_VEXL | ENC_VM | PREF_66, AVX},
	},
	"vpsrlq": {
		spec{"y*y*ib", op{0x01, 0x73}, 2, VEX_OP | ENC_VM | PREF_66, AVX},
		spec{"y*y*wo", op{0x01, 0xD3}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsrlvd": {
		spec{"y*y*w*", op{0x02, 0x45}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX2},
	},
	"vpsrlvq": {
		spec{"y*y*w*", op{0x02, 0x45}, X, VEX_OP | AUTO_VEXL | WITH_REXW | PREF_66, AVX2},
	},
	"vpsrlw": {
		spec{"y*y*ib", op{0x01, 0x71}, 2, VEX_OP | AUTO_VEXL | ENC_VM | PREF_66, AVX},
		spec{"y*y*wo", op{0x01, 0xD1}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsubb": {
		spec{"y*y*w*", op{0x01, 0xF8}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsubd": {
		spec{"y*y*w*", op{0x01, 0xFA}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsubq": {
		spec{"y*y*w*", op{0x01, 0xFB}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsubsb": {
		spec{"y*y*w*", op{0x01, 0xE8}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsubsw": {
		spec{"y*y*w*", op{0x01, 0xE9}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsubusb": {
		spec{"y*y*w*", op{0x01, 0xD8}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsubusw": {
		spec{"y*y*w*", op{0x01, 0xD9}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpsubw": {
		spec{"y*y*w*", op{0x01, 0xF9}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vptest": {
		spec{"y*w*", op{0x02, 0x17}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpunpckhbw": {
		spec{"y*y*w*", op{0x01, 0x68}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpunpckhdq": {
		spec{"y*y*w*", op{0x01, 0x6A}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpunpckhqdq": {
		spec{"y*y*w*", op{0x01, 0x6D}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpunpckhwd": {
		spec{"y*y*w*", op{0x01, 0x69}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpunpcklbw": {
		spec{"y*y*w*", op{0x01, 0x60}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpunpckldq": {
		spec{"y*y*w*", op{0x01, 0x62}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpunpcklqdq": {
		spec{"y*y*w*", op{0x01, 0x6C}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpunpcklwd": {
		spec{"y*y*w*", op{0x01, 0x61}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vpxor": {
		spec{"y*y*w*", op{0x01, 0xEF}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vrcpps": {
		spec{"y*w*", op{0x01, 0x53}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vrcpss": {
		spec{"yoyomd", op{0x01, 0x53}, X, VEX_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0x53}, X, VEX_OP | PREF_F3, AVX},
	},
	"vroundpd": {
		spec{"y*w*ib", op{0x03, 0x09}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vroundps": {
		spec{"y*w*ib", op{0x03, 0x08}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vroundsd": {
		spec{"yoyomqib", op{0x03, 0x0B}, X, VEX_OP | PREF_66, AVX},
		spec{"yoyoyoib", op{0x03, 0x0B}, X, VEX_OP | PREF_66, AVX},
	},
	"vroundss": {
		spec{"yoyomdib", op{0x03, 0x0A}, X, VEX_OP | PREF_66, AVX},
		spec{"yoyoyoib", op{0x03, 0x0A}, X, VEX_OP | PREF_66, AVX},
	},
	"vrsqrtps": {
		spec{"y*w*", op{0x01, 0x52}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vrsqrtss": {
		spec{"yoyomd", op{0x01, 0x52}, X, VEX_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0x52}, X, VEX_OP | PREF_F3, AVX},
	},
	"vshufpd": {
		spec{"y*y*w*ib", op{0x01, 0xC6}, X, VEX_OP | AUTO_VEXL | ENC_MR | PREF_66, AVX},
	},
	"vshufps": {
		spec{"y*y*w*ib", op{0x01, 0xC6}, X, VEX_OP | AUTO_VEXL | ENC_MR, AVX},
	},
	"vsqrtpd": {
		spec{"y*w*", op{0x01, 0x51}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vsqrtps": {
		spec{"y*w*", op{0x01, 0x51}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vsqrtsd": {
		spec{"yoyomq", op{0x01, 0x51}, X, VEX_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0x51}, X, VEX_OP | PREF_F2, AVX},
	},
	"vsqrtss": {
		spec{"yoyomd", op{0x01, 0x51}, X, VEX_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0x51}, X, VEX_OP | PREF_F3, AVX},
	},
	"vstmxcsr": {
		spec{"md", op{0x01, 0xAE}, 3, VEX_OP, AVX},
	},
	"vsubpd": {
		spec{"y*y*w*", op{0x01, 0x5C}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vsubps": {
		spec{"y*y*w*", op{0x01, 0x5C}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vsubsd": {
		spec{"yoyomq", op{0x01, 0x5C}, X, VEX_OP | PREF_F2, AVX},
		spec{"yoyoyo", op{0x01, 0x5C}, X, VEX_OP | PREF_F2, AVX},
	},
	"vsubss": {
		spec{"yoyomd", op{0x01, 0x5C}, X, VEX_OP | PREF_F3, AVX},
		spec{"yoyoyo", op{0x01, 0x5C}, X, VEX_OP | PREF_F3, AVX},
	},
	"vtestpd": {
		spec{"y*w*", op{0x02, 0x0F}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vtestps": {
		spec{"y*w*", op{0x02, 0x0E}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vucomisd": {
		spec{"yomq", op{0x01, 0x2E}, X, VEX_OP | PREF_66, AVX},
		spec{"yoyo", op{0x01, 0x2E}, X, VEX_OP | PREF_66, AVX},
	},
	"vucomiss": {
		spec{"yomd", op{0x01, 0x2E}, X, VEX_OP, AVX},
		spec{"yoyo", op{0x01, 0x2E}, X, VEX_OP, AVX},
	},
	"vunpckhpd": {
		spec{"y*y*w*", op{0x01, 0x15}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vunpckhps": {
		spec{"y*y*w*", op{0x01, 0x15}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vunpcklpd": {
		spec{"y*y*w*", op{0x01, 0x14}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vunpcklps": {
		spec{"y*y*w*", op{0x01, 0x14}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vxorpd": {
		spec{"y*y*w*", op{0x01, 0x57}, X, VEX_OP | AUTO_VEXL | PREF_66, AVX},
	},
	"vxorps": {
		spec{"y*y*w*", op{0x01, 0x57}, X, VEX_OP | AUTO_VEXL, AVX},
	},
	"vzeroall": {
		spec{"", op{0x01, 0x77}, X, WITH_VEXL | VEX_OP, AVX},
	},
	"vzeroupper": {
		spec{"", op{0x01, 0x77}, X, VEX_OP, AVX},
	},
	"wbinvd": {
		spec{"", op{0x0F, 0x09}, X, DEFAULT, X64_IMPLICIT},
	},
	"wrfsbase": {
		spec{"rd", op{0x0F, 0xAE}, 2, PREF_F3, X64_IMPLICIT},
		spec{"rq", op{0x0F, 0xAE}, 2, WITH_REXW | PREF_F3, X64_IMPLICIT},
	},
	"wrgsbase": {
		spec{"rd", op{0x0F, 0xAE}, 3, PREF_F3, X64_IMPLICIT},
		spec{"rq", op{0x0F, 0xAE}, 3, WITH_REXW | PREF_F3, X64_IMPLICIT},
	},
	"wrmsr": {
		spec{"", op{0x0F, 0x30}, X, DEFAULT, X64_IMPLICIT},
	},
	"wrpkru": {
		spec{"", op{0x0F, 0x01, 0xEF}, X, DEFAULT, X64_IMPLICIT},
	},
	"wrshr": {
		spec{"vd", op{0x0F, 0x37}, 0, DEFAULT, CYRIX},
	},
	"xabort": {
		spec{"ib", op{0xC6, 0xF8}, X, DEFAULT, RTM},
	},
	"xadd": {
		spec{"mbrb", op{0x0F, 0xC0}, X, LOCK | ENC_MR, X64_IMPLICIT},
		spec{"rbrb", op{0x0F, 0xC0}, X, ENC_MR, X64_IMPLICIT},
		spec{"m*r*", op{0x0F, 0xC1}, X, AUTO_SIZE | LOCK | ENC_MR, X64_IMPLICIT},
		spec{"r*r*", op{0x0F, 0xC1}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
	},
	"xbegin": {
		spec{"od", op{0xC7, 0xF8}, X, DEFAULT, RTM},
	},
	"xchg": {
		spec{"mbrb", op{0x86}, X, LOCK | ENC_MR, X64_IMPLICIT},
		spec{"rbmb", op{0x86}, X, LOCK, X64_IMPLICIT},
		spec{"rbrb", op{0x86}, X, DEFAULT, X64_IMPLICIT},
		spec{"rbrb", op{0x86}, X, ENC_MR, X64_IMPLICIT},
		spec{"A*r*", op{0x90}, X, AUTO_SIZE | SHORT_ARG, X64_IMPLICIT},
		spec{"m*r*", op{0x87}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
		spec{"r*A*", op{0x90}, X, AUTO_SIZE | SHORT_ARG, X64_IMPLICIT},
		spec{"r*m*", op{0x87}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*r*", op{0x87}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*r*", op{0x87}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
	},
	"xcryptcbc": {
		spec{"", op{0x0F, 0xA7, 0xD0}, X, PREF_F3, CYRIX},
	},
	"xcryptcfb": {
		spec{"", op{0x0F, 0xA7, 0xE0}, X, PREF_F3, CYRIX},
	},
	"xcryptctr": {
		spec{"", op{0x0F, 0xA7, 0xD8}, X, PREF_F3, CYRIX},
	},
	"xcryptecb": {
		spec{"", op{0x0F, 0xA7, 0xC8}, X, PREF_F3, CYRIX},
	},
	"xcryptofb": {
		spec{"", op{0x0F, 0xA7, 0xE8}, X, PREF_F3, CYRIX},
	},
	"xend": {
		spec{"", op{0x0F, 0x01, 0xD5}, X, DEFAULT, RTM},
	},
	"xgetbv": {
		spec{"", op{0x0F, 0x01, 0xD0}, X, DEFAULT, X64_IMPLICIT},
	},
	"xlat": {
		spec{"", op{0xD7}, X, DEFAULT, X64_IMPLICIT},
	},
	"xlatb": {
		spec{"", op{0xD7}, X, DEFAULT, X64_IMPLICIT},
	},
	"xor": {
		spec{"Abib", op{0x34}, X, DEFAULT, X64_IMPLICIT},
		spec{"mbib", op{0x80}, 6, LOCK, X64_IMPLICIT},
		spec{"mbrb", op{0x30}, X, LOCK | ENC_MR, X64_IMPLICIT},
		spec{"rbib", op{0x80}, 6, DEFAULT, X64_IMPLICIT},
		spec{"rbrb", op{0x30}, X, ENC_MR, X64_IMPLICIT},
		spec{"rbvb", op{0x32}, X, DEFAULT, X64_IMPLICIT},
		spec{"r*ib", op{0x83}, 6, AUTO_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"A*i*", op{0x35}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"m*i*", op{0x81}, 6, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*ib", op{0x83}, 6, AUTO_SIZE | LOCK, X64_IMPLICIT},
		spec{"m*r*", op{0x31}, X, AUTO_SIZE | LOCK | ENC_MR, X64_IMPLICIT},
		spec{"r*i*", op{0x81}, 6, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*r*", op{0x31}, X, AUTO_SIZE | ENC_MR, X64_IMPLICIT},
		spec{"r*v*", op{0x33}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"xorpd": {
		spec{"yowo", op{0x0F, 0x57}, X, PREF_66, SSE2},
	},
	"xorps": {
		spec{"yowo", op{0x0F, 0x57}, X, DEFAULT, SSE},
	},
	"xrstor": {
		spec{"m!", op{0x0F, 0xAE}, 5, DEFAULT, X64_IMPLICIT},
	},
	"xrstor64": {
		spec{"m!", op{0x0F, 0xAE}, 5, WITH_REXW, X64_IMPLICIT},
	},
	"xrstors64": {
		spec{"m!", op{0x0F, 0xC7}, 3, WITH_REXW, X64_IMPLICIT},
	},
	"xsave": {
		spec{"m!", op{0x0F, 0xAE}, 4, DEFAULT, X64_IMPLICIT},
	},
	"xsave64": {
		spec{"m!", op{0x0F, 0xAE}, 4, WITH_REXW, X64_IMPLICIT},
	},
	"xsavec64": {
		spec{"m!", op{0x0F, 0xC7}, 4, WITH_REXW, X64_IMPLICIT},
	},
	"xsaveopt64": {
		spec{"m!", op{0x0F, 0xAE}, 6, WITH_REXW, X64_IMPLICIT},
	},
	"xsaves64": {
		spec{"m!", op{0x0F, 0xC7}, 5, WITH_REXW, X64_IMPLICIT},
	},
	"xsetbv": {
		spec{"", op{0x0F, 0x01, 0xD1}, X, DEFAULT, X64_IMPLICIT},
	},
	"xsha1": {
		spec{"", op{0x0F, 0xA6, 0xC8}, X, PREF_F3, CYRIX},
	},
	"xsha256": {
		spec{"", op{0x0F, 0xA6, 0xD0}, X, PREF_F3, CYRIX},
	},
	"xstore": {
		spec{"", op{0x0F, 0xA7, 0xC0}, X, DEFAULT, CYRIX},
	},
	"xtest": {
		spec{"", op{0x0F, 0x01, 0xD6}, X, DEFAULT, RTM},
	},
	"call": {
		spec{"iwiw", op{0x9A}, X, X86_ONLY | WORD_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"idiw", op{0x9A}, X, X86_ONLY, X64_IMPLICIT},
		spec{"mf", op{0xFF}, 3, X86_ONLY | EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0xE8}, X, DEFAULT, X64_IMPLICIT},
		spec{"v*", op{0xFF}, 2, AUTO_NO32, X64_IMPLICIT},
	},
	"callf": {
		spec{"iwiw", op{0x9A}, X, X86_ONLY | WORD_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"idiw", op{0x9A}, X, X86_ONLY, X64_IMPLICIT},
		spec{"md", op{0xFF}, 3, X86_ONLY | WORD_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"mf", op{0xFF}, 3, X86_ONLY, X64_IMPLICIT},
	},
	"jmp": {
		spec{"iwiw", op{0x9A}, X, X86_ONLY | WORD_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"idiw", op{0xEA}, X, X86_ONLY, X64_IMPLICIT},
		spec{"mf", op{0xFF}, 5, X86_ONLY | EXACT_SIZE, X64_IMPLICIT},
		spec{"ob", op{0xEB}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0xE9}, X, DEFAULT, X64_IMPLICIT},
		spec{"v*", op{0xFF}, 4, AUTO_NO32, X64_IMPLICIT},
	},
	"jmpf": {
		spec{"iwiw", op{0x9A}, X, X86_ONLY | WORD_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"idiw", op{0xEA}, X, X86_ONLY, X64_IMPLICIT},
		spec{"md", op{0xFF}, 5, X86_ONLY | WORD_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"mf", op{0xFF}, 5, X86_ONLY, X64_IMPLICIT},
	},
	"mov": {
		spec{"v*r*", op{0x89}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"vbrb", op{0x88}, X, DEFAULT, X64_IMPLICIT},
		spec{"r*v*", op{0x8B}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"rbvb", op{0x8A}, X, DEFAULT, X64_IMPLICIT},
		spec{"r*sw", op{0x8C}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"mwsw", op{0x8C}, X, DEFAULT, X64_IMPLICIT},
		spec{"swmw", op{0x8C}, X, DEFAULT, X64_IMPLICIT},
		spec{"swrw", op{0x8C}, X, DEFAULT, X64_IMPLICIT},
		spec{"rbib", op{0xB0}, X, SHORT_ARG, X64_IMPLICIT},
		spec{"rwiw", op{0xB8}, X, WORD_SIZE | SHORT_ARG, X64_IMPLICIT},
		spec{"rdid", op{0xB8}, X, SHORT_ARG, X64_IMPLICIT},
		spec{"v*i*", op{0xC7}, 0, AUTO_SIZE, X64_IMPLICIT},
		spec{"vbib", op{0xC6}, 0, DEFAULT, X64_IMPLICIT},
		spec{"rqiq", op{0xB8}, X, WITH_REXW | SHORT_ARG, X64_IMPLICIT},
		spec{"cdrd", op{0x0F, 0x22}, X, DEFAULT, X64_IMPLICIT},
		spec{"cqrq", op{0x0F, 0x22}, X, DEFAULT, X64_IMPLICIT},
		spec{"rdcd", op{0x0F, 0x20}, X, DEFAULT, X64_IMPLICIT},
		spec{"rqcq", op{0x0F, 0x20}, X, DEFAULT, X64_IMPLICIT},
		spec{"Wdrd", op{0x0F, 0x22}, 0, PREF_F0, X64_IMPLICIT},
		spec{"Wqrq", op{0x0F, 0x22}, 0, PREF_F0, X64_IMPLICIT},
		spec{"rdWd", op{0x0F, 0x22}, 0, PREF_F0, X64_IMPLICIT},
		spec{"rqWq", op{0x0F, 0x22}, 0, PREF_F0, X64_IMPLICIT},
		spec{"ddrd", op{0x0F, 0x23}, X, DEFAULT, X64_IMPLICIT},
		spec{"dqrq", op{0x0F, 0x23}, X, DEFAULT, X64_IMPLICIT},
		spec{"rddd", op{0x0F, 0x21}, X, DEFAULT, X64_IMPLICIT},
		spec{"rqdq", op{0x0F, 0x21}, X, DEFAULT, X64_IMPLICIT},
	},
	"movabs": {
		spec{"Abiq", op{0xA0}, X, DEFAULT, X64_IMPLICIT},
		spec{"Awiq", op{0xA1}, X, WORD_SIZE, X64_IMPLICIT},
		spec{"Adiq", op{0xA1}, X, DEFAULT, X64_IMPLICIT},
		spec{"Aqiq", op{0xA1}, X, WITH_REXW, X64_IMPLICIT},
		spec{"iqAb", op{0xA2}, X, DEFAULT, X64_IMPLICIT},
		spec{"iqAw", op{0xA3}, X, WORD_SIZE, X64_IMPLICIT},
		spec{"iqAd", op{0xA3}, X, DEFAULT, X64_IMPLICIT},
		spec{"iqAq", op{0xA3}, X, WITH_REXW, X64_IMPLICIT},
	},
	"jo": {
		spec{"ob", op{0x70}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x80}, X, DEFAULT, X64_IMPLICIT},
	},
	"jno": {
		spec{"ob", op{0x71}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x81}, X, DEFAULT, X64_IMPLICIT},
	},
	"jb": {
		spec{"ob", op{0x72}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x82}, X, DEFAULT, X64_IMPLICIT},
	},
	"jc": {
		spec{"ob", op{0x72}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x82}, X, DEFAULT, X64_IMPLICIT},
	},
	"jnae": {
		spec{"ob", op{0x72}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x82}, X, DEFAULT, X64_IMPLICIT},
	},
	"jnb": {
		spec{"ob", op{0x73}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x83}, X, DEFAULT, X64_IMPLICIT},
	},
	"jnc": {
		spec{"ob", op{0x73}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x83}, X, DEFAULT, X64_IMPLICIT},
	},
	"jae": {
		spec{"ob", op{0x73}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x83}, X, DEFAULT, X64_IMPLICIT},
	},
	"jz": {
		spec{"ob", op{0x74}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x84}, X, DEFAULT, X64_IMPLICIT},
	},
	"je": {
		spec{"ob", op{0x74}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x84}, X, DEFAULT, X64_IMPLICIT},
	},
	"jnz": {
		spec{"ob", op{0x75}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x85}, X, DEFAULT, X64_IMPLICIT},
	},
	"jne": {
		spec{"ob", op{0x75}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x85}, X, DEFAULT, X64_IMPLICIT},
	},
	"jbe": {
		spec{"ob", op{0x76}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x86}, X, DEFAULT, X64_IMPLICIT},
	},
	"jna": {
		spec{"ob", op{0x76}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x86}, X, DEFAULT, X64_IMPLICIT},
	},
	"jnbe": {
		spec{"ob", op{0x77}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x87}, X, DEFAULT, X64_IMPLICIT},
	},
	"ja": {
		spec{"ob", op{0x77}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x87}, X, DEFAULT, X64_IMPLICIT},
	},
	"js": {
		spec{"ob", op{0x78}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x88}, X, DEFAULT, X64_IMPLICIT},
	},
	"jns": {
		spec{"ob", op{0x79}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x89}, X, DEFAULT, X64_IMPLICIT},
	},
	"jp": {
		spec{"ob", op{0x7A}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x8A}, X, DEFAULT, X64_IMPLICIT},
	},
	"jpe": {
		spec{"ob", op{0x7A}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x8A}, X, DEFAULT, X64_IMPLICIT},
	},
	"jnp": {
		spec{"ob", op{0x7B}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x8B}, X, DEFAULT, X64_IMPLICIT},
	},
	"jpo": {
		spec{"ob", op{0x7B}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x8B}, X, DEFAULT, X64_IMPLICIT},
	},
	"jl": {
		spec{"ob", op{0x7C}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x8C}, X, DEFAULT, X64_IMPLICIT},
	},
	"jnge": {
		spec{"ob", op{0x7C}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x8C}, X, DEFAULT, X64_IMPLICIT},
	},
	"jnl": {
		spec{"ob", op{0x7D}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x8D}, X, DEFAULT, X64_IMPLICIT},
	},
	"jge": {
		spec{"ob", op{0x7D}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x8D}, X, DEFAULT, X64_IMPLICIT},
	},
	"jle": {
		spec{"ob", op{0x7E}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x8E}, X, DEFAULT, X64_IMPLICIT},
	},
	"jng": {
		spec{"ob", op{0x7E}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x8E}, X, DEFAULT, X64_IMPLICIT},
	},
	"jnle": {
		spec{"ob", op{0x7F}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x8F}, X, DEFAULT, X64_IMPLICIT},
	},
	"jg": {
		spec{"ob", op{0x7F}, X, EXACT_SIZE, X64_IMPLICIT},
		spec{"od", op{0x0F, 0x8F}, X, DEFAULT, X64_IMPLICIT},
	},
	"cmovo": {
		spec{"r*v*", op{0x0F, 0x40}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovno": {
		spec{"r*v*", op{0x0F, 0x41}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovb": {
		spec{"r*v*", op{0x0F, 0x42}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovc": {
		spec{"r*v*", op{0x0F, 0x42}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovnae": {
		spec{"r*v*", op{0x0F, 0x42}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovnb": {
		spec{"r*v*", op{0x0F, 0x43}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovnc": {
		spec{"r*v*", op{0x0F, 0x43}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovae": {
		spec{"r*v*", op{0x0F, 0x43}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovz": {
		spec{"r*v*", op{0x0F, 0x44}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmove": {
		spec{"r*v*", op{0x0F, 0x44}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovnz": {
		spec{"r*v*", op{0x0F, 0x45}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovne": {
		spec{"r*v*", op{0x0F, 0x45}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovbe": {
		spec{"r*v*", op{0x0F, 0x46}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovna": {
		spec{"r*v*", op{0x0F, 0x46}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovnbe": {
		spec{"r*v*", op{0x0F, 0x47}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmova": {
		spec{"r*v*", op{0x0F, 0x47}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovs": {
		spec{"r*v*", op{0x0F, 0x48}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovns": {
		spec{"r*v*", op{0x0F, 0x49}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovp": {
		spec{"r*v*", op{0x0F, 0x4A}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovpe": {
		spec{"r*v*", op{0x0F, 0x4A}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovnp": {
		spec{"r*v*", op{0x0F, 0x4B}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovpo": {
		spec{"r*v*", op{0x0F, 0x4B}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovl": {
		spec{"r*v*", op{0x0F, 0x4C}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovnge": {
		spec{"r*v*", op{0x0F, 0x4C}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovnl": {
		spec{"r*v*", op{0x0F, 0x4D}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovge": {
		spec{"r*v*", op{0x0F, 0x4D}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovle": {
		spec{"r*v*", op{0x0F, 0x4E}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovng": {
		spec{"r*v*", op{0x0F, 0x4E}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovnle": {
		spec{"r*v*", op{0x0F, 0x4F}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"cmovg": {
		spec{"r*v*", op{0x0F, 0x4F}, X, AUTO_SIZE, X64_IMPLICIT},
	},
	"seto": {
		spec{"vb", op{0x0F, 0x90}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setno": {
		spec{"vb", op{0x0F, 0x91}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setb": {
		spec{"vb", op{0x0F, 0x92}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setc": {
		spec{"vb", op{0x0F, 0x92}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setnae": {
		spec{"vb", op{0x0F, 0x92}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setnb": {
		spec{"vb", op{0x0F, 0x93}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setnc": {
		spec{"vb", op{0x0F, 0x93}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setae": {
		spec{"vb", op{0x0F, 0x93}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setz": {
		spec{"vb", op{0x0F, 0x94}, 0, DEFAULT, X64_IMPLICIT},
	},
	"sete": {
		spec{"vb", op{0x0F, 0x94}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setnz": {
		spec{"vb", op{0x0F, 0x95}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setne": {
		spec{"vb", op{0x0F, 0x95}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setbe": {
		spec{"vb", op{0x0F, 0x96}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setna": {
		spec{"vb", op{0x0F, 0x96}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setnbe": {
		spec{"vb", op{0x0F, 0x97}, 0, DEFAULT, X64_IMPLICIT},
	},
	"seta": {
		spec{"vb", op{0x0F, 0x97}, 0, DEFAULT, X64_IMPLICIT},
	},
	"sets": {
		spec{"vb", op{0x0F, 0x98}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setns": {
		spec{"vb", op{0x0F, 0x99}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setp": {
		spec{"vb", op{0x0F, 0x9A}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setpe": {
		spec{"vb", op{0x0F, 0x9A}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setnp": {
		spec{"vb", op{0x0F, 0x9B}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setpo": {
		spec{"vb", op{0x0F, 0x9B}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setl": {
		spec{"vb", op{0x0F, 0x9C}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setnge": {
		spec{"vb", op{0x0F, 0x9C}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setnl": {
		spec{"vb", op{0x0F, 0x9D}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setge": {
		spec{"vb", op{0x0F, 0x9D}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setle": {
		spec{"vb", op{0x0F, 0x9E}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setng": {
		spec{"vb", op{0x0F, 0x9E}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setnle": {
		spec{"vb", op{0x0F, 0x9F}, 0, DEFAULT, X64_IMPLICIT},
	},
	"setg": {
		spec{"vb", op{0x0F, 0x9F}, 0, DEFAULT, X64_IMPLICIT},
	},
	"in": {
		spec{"Abib", op{0xE4}, X, DEFAULT, X64_IMPLICIT},
		spec{"Awib", op{0xE5}, X, WORD_SIZE, X64_IMPLICIT},
		spec{"Adib", op{0xE5}, X, DEFAULT, X64_IMPLICIT},
		spec{"AbCw", op{0xEC}, X, DEFAULT, X64_IMPLICIT},
		spec{"AwCw", op{0xED}, X, WORD_SIZE, X64_IMPLICIT},
		spec{"AdCw", op{0xED}, X, DEFAULT, X64_IMPLICIT},
	},
	"out": {
		spec{"ibAb", op{0xE6}, X, DEFAULT, X64_IMPLICIT},
		spec{"ibAw", op{0xE7}, X, DEFAULT, X64_IMPLICIT},
		spec{"ibAd", op{0xE7}, X, DEFAULT, X64_IMPLICIT},
		spec{"CwAb", op{0xEE}, X, DEFAULT, X64_IMPLICIT},
		spec{"CwAw", op{0xEF}, X, WORD_SIZE, X64_IMPLICIT},
		spec{"CwAd", op{0xEF}, X, DEFAULT, X64_IMPLICIT},
	},
	"crc32": {
		spec{"r*vb", op{0x0F, 0x38, 0xF0}, X, AUTO_REXW | PREF_F2 | EXACT_SIZE, X64_IMPLICIT},
		spec{"rdvw", op{0x0F, 0x38, 0xF1}, X, WORD_SIZE | PREF_F2 | EXACT_SIZE, X64_IMPLICIT},
		spec{"r*v*", op{0x0F, 0x38, 0xF1}, X, AUTO_REXW | PREF_F2 | EXACT_SIZE, X64_IMPLICIT},
	},
	"imul": {
		spec{"v*", op{0xF7}, 5, AUTO_SIZE, X64_IMPLICIT},
		spec{"vb", op{0xF6}, 5, DEFAULT, X64_IMPLICIT},
		spec{"r*v*", op{0x0F, 0xAF}, X, AUTO_SIZE, X64_IMPLICIT},
		spec{"r*v*ib", op{0x6B}, X, AUTO_SIZE | EXACT_SIZE, X64_IMPLICIT},
		spec{"r*v*i*", op{0x69}, X, AUTO_SIZE, X64_IMPLICIT},
	},
}
