package x64

type ConditionCode byte

const (
	CCUnsignedLT  ConditionCode = 2
	CCUnsignedGTE ConditionCode = 3
	CCEq          ConditionCode = 4
	CCNeq         ConditionCode = 5
	CCUnsignedLTE ConditionCode = 6
	CCUnsignedGT  ConditionCode = 7
	CCSignedLT    ConditionCode = 0xC
	CCSignedGTE   ConditionCode = 0xD
	CCSignedLTE   ConditionCode = 0xE
	CCSignedGT    ConditionCode = 0xF
)

var invccTable = [...]ConditionCode{
	CCUnsignedGTE, // CCUnsignedLT
	CCUnsignedLT,  // CCUnsignedGTE
	CCNeq,         // CCEq
	CCEq,          // CCNeq
	CCUnsignedGT,  // CCUnsignedLTE
	CCUnsignedLTE, // CCUnsignedGT
	CCSignedGTE,   // CCSignedLT
	CCSignedLT,    // CCSignedGTE
	CCSignedGT,    // CCSignedLTE
	CCSignedLTE,   // CCSignedGT
}

var jccTable = [...]Inst{
	JB,   // CCUnsignedLT
	JNB,  // CCUnsignedGTE
	JZ,   // CCEq
	JNZ,  // CCNeq
	JBE,  // CCUnsignedLTE
	JNBE, // CCUnsignedGT
	JL,   // CCSignedLT
	JNL,  // CCSignedGTE
	JLE,  // CCSignedLTE
	JNLE, // CCSignedGT
}

var setccTable = [...]Inst{
	SETB,   // CCUnsignedLT
	SETNB,  // CCUnsignedGTE
	SETZ,   // CCEq
	SETNZ,  // CCNeq
	SETBE,  // CCUnsignedLTE
	SETNBE, // CCUnsignedGT
	SETL,   // CCSignedLT
	SETNL,  // CCSignedGTE
	SETLE,  // CCSignedLTE
	SETNLE, // CCSignedGT
}

var cmovccTable = [...]Inst{
	CMOVB,   // CCUnsignedLT
	CMOVNB,  // CCUnsignedGTE
	CMOVZ,   // CCEq
	CMOVNZ,  // CCNeq
	CMOVBE,  // CCUnsignedLTE
	CMOVNBE, // CCUnsignedGT
	CMOVL,   // CCSignedLT
	CMOVNL,  // CCSignedGTE
	CMOVLE,  // CCSignedLTE
	CMOVNLE, // CCSignedGT
}

func ccTableOffset(cc ConditionCode) uint8 {
	if cc < CCSignedLT {
		return uint8(cc - CCUnsignedLT)
	}
	return uint8(((CCUnsignedGT + 1) - CCUnsignedLT) + (cc - CCSignedLT))
}

// Get the conditional-jump instruction for a condition code.
func Jcc(cc ConditionCode) Inst { return jccTable[ccTableOffset(cc)] }

// Get the conditional-set instruction for a condition code.
func Setcc(cc ConditionCode) Inst { return setccTable[ccTableOffset(cc)] }

// Get the conditional-move instruction for a condition code.
func Cmovcc(cc ConditionCode) Inst { return cmovccTable[ccTableOffset(cc)] }

// Invert a condition code.
func Invcc(cc ConditionCode) ConditionCode { return invccTable[ccTableOffset(cc)] }
