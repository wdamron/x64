package x64flags

// Flags
const (
	DEFAULT uint32 = 0         // this instruction has default encoding
	VEX_OP  uint32 = 1 << iota // this instruction requires a VEX prefix to be encoded
	XOP_OP                     // this instruction requires a XOP prefix to be encoded
	IMM_OP                     // this instruction encodes the final opcode byte in the immediate position, like 3DNow! ops.

	// note: the first 4 in this block are mutually exclusive
	AUTO_SIZE  // 16 bit -> OPSIZE , 32-bit -> None     , 64-bit -> REX.W/VEX.W/XOP.W
	AUTO_NO32  // 16 bit -> OPSIZE , 32-bit -> None(x86), 64-bit -> None(x64)
	AUTO_REXW  // 16 bit -> illegal, 32-bit -> None     , 64-bit -> REX.W/VEX.W/XOP.W
	AUTO_VEXL  // 128bit -> None   , 256bit -> VEX.L
	WORD_SIZE  // implies opsize prefix
	WITH_REXW  // implies REX.W/VEX.W/XOP.W
	WITH_VEXL  // implies VEX.L/XOP.L
	EXACT_SIZE // operands with unknown sizes cannot be assumed to match

	PREF_66 // mandatory prefix (same as WORD_SIZE)
	PREF_67 // mandatory prefix (same as SMALL_ADDRESS)
	PREF_F0 // mandatory prefix (same as LOCK)
	PREF_F2 // mandatory prefix (REPNE)
	PREF_F3 // mandatory prefix (REP)

	LOCK // user lock prefix is valid with this instruction
	REP  // user rep prefix is valid with this instruction
	REPE

	SHORT_ARG // a register argument is encoded in the last byte of the opcode
	ENC_MR    // select alternate arg encoding
	ENC_VM    // select alternate arg encoding
	ENC_MIB   // A special encoding using the SIB to specify an immediate and two registers
	X86_ONLY  // instructions available in protected mode, but not long mode
)

func FlagName(f uint32) string { return flagNames[f] }

var flagNames = map[uint32]string{
	DEFAULT:    "DEFAULT",
	VEX_OP:     "VEX_OP",
	XOP_OP:     "XOP_OP",
	IMM_OP:     "IMM_OP",
	AUTO_SIZE:  "AUTO_SIZE",
	AUTO_NO32:  "AUTO_NO32",
	AUTO_REXW:  "AUTO_REXW",
	AUTO_VEXL:  "AUTO_VEXL",
	WORD_SIZE:  "WORD_SIZE",
	WITH_REXW:  "WITH_REXW",
	WITH_VEXL:  "WITH_VEXL",
	EXACT_SIZE: "EXACT_SIZE",
	PREF_66:    "PREF_66",
	PREF_67:    "PREF_67",
	PREF_F0:    "PREF_F0",
	PREF_F2:    "PREF_F2",
	PREF_F3:    "PREF_F3",
	LOCK:       "LOCK",
	REP:        "REP",
	REPE:       "REPE",
	SHORT_ARG:  "SHORT_ARG",
	ENC_MR:     "ENC_MR",
	ENC_VM:     "ENC_VM",
	ENC_MIB:    "ENC_MIB",
	X86_ONLY:   "X86_ONLY",
}
