package x64

// Register families
const (
	REG_LEGACY   = iota
	REG_RIP      // IP, EIP, RIP
	REG_HIGHBYTE // AH, CH, DH, BH
	REG_FP
	REG_MMX
	REG_XMM
	REG_YMM
	REG_SEGMENT
	REG_CONTROL
	REG_DEBUG
)

// Registers
const (
	// 8-bit
	AH   Reg = Reg(1<<16 | REG_HIGHBYTE<<8 | 4)
	CH   Reg = Reg(1<<16 | REG_HIGHBYTE<<8 | 5)
	DH   Reg = Reg(1<<16 | REG_HIGHBYTE<<8 | 6)
	BH   Reg = Reg(1<<16 | REG_HIGHBYTE<<8 | 7)
	AL   Reg = Reg(1<<16 | REG_LEGACY<<8 | 0)
	CL   Reg = Reg(1<<16 | REG_LEGACY<<8 | 1)
	DL   Reg = Reg(1<<16 | REG_LEGACY<<8 | 2)
	BL   Reg = Reg(1<<16 | REG_LEGACY<<8 | 3)
	SPB  Reg = Reg(1<<16 | REG_LEGACY<<8 | 4)
	BPB  Reg = Reg(1<<16 | REG_LEGACY<<8 | 5)
	SIB  Reg = Reg(1<<16 | REG_LEGACY<<8 | 6)
	DIB  Reg = Reg(1<<16 | REG_LEGACY<<8 | 7)
	R8B  Reg = Reg(1<<16 | REG_LEGACY<<8 | 8)
	R9B  Reg = Reg(1<<16 | REG_LEGACY<<8 | 9)
	R10B Reg = Reg(1<<16 | REG_LEGACY<<8 | 10)
	R11B Reg = Reg(1<<16 | REG_LEGACY<<8 | 11)
	R12B Reg = Reg(1<<16 | REG_LEGACY<<8 | 12)
	R13B Reg = Reg(1<<16 | REG_LEGACY<<8 | 13)
	R14B Reg = Reg(1<<16 | REG_LEGACY<<8 | 14)
	R15B Reg = Reg(1<<16 | REG_LEGACY<<8 | 15)

	// 16-bit
	AX   Reg = Reg(2<<16 | REG_LEGACY<<8 | 0)
	CX   Reg = Reg(2<<16 | REG_LEGACY<<8 | 1)
	DX   Reg = Reg(2<<16 | REG_LEGACY<<8 | 2)
	BX   Reg = Reg(2<<16 | REG_LEGACY<<8 | 3)
	SP   Reg = Reg(2<<16 | REG_LEGACY<<8 | 4)
	BP   Reg = Reg(2<<16 | REG_LEGACY<<8 | 5)
	SI   Reg = Reg(2<<16 | REG_LEGACY<<8 | 6)
	DI   Reg = Reg(2<<16 | REG_LEGACY<<8 | 7)
	R8W  Reg = Reg(2<<16 | REG_LEGACY<<8 | 8)
	R9W  Reg = Reg(2<<16 | REG_LEGACY<<8 | 9)
	R10W Reg = Reg(2<<16 | REG_LEGACY<<8 | 10)
	R11W Reg = Reg(2<<16 | REG_LEGACY<<8 | 11)
	R12W Reg = Reg(2<<16 | REG_LEGACY<<8 | 12)
	R13W Reg = Reg(2<<16 | REG_LEGACY<<8 | 13)
	R14W Reg = Reg(2<<16 | REG_LEGACY<<8 | 14)
	R15W Reg = Reg(2<<16 | REG_LEGACY<<8 | 15)

	// 32-bit
	EAX  Reg = Reg(4<<16 | REG_LEGACY<<8 | 0)
	ECX  Reg = Reg(4<<16 | REG_LEGACY<<8 | 1)
	EDX  Reg = Reg(4<<16 | REG_LEGACY<<8 | 2)
	EBX  Reg = Reg(4<<16 | REG_LEGACY<<8 | 3)
	ESP  Reg = Reg(4<<16 | REG_LEGACY<<8 | 4)
	EBP  Reg = Reg(4<<16 | REG_LEGACY<<8 | 5)
	ESI  Reg = Reg(4<<16 | REG_LEGACY<<8 | 6)
	EDI  Reg = Reg(4<<16 | REG_LEGACY<<8 | 7)
	R8L  Reg = Reg(4<<16 | REG_LEGACY<<8 | 8)
	R9L  Reg = Reg(4<<16 | REG_LEGACY<<8 | 9)
	R10L Reg = Reg(4<<16 | REG_LEGACY<<8 | 10)
	R11L Reg = Reg(4<<16 | REG_LEGACY<<8 | 11)
	R12L Reg = Reg(4<<16 | REG_LEGACY<<8 | 12)
	R13L Reg = Reg(4<<16 | REG_LEGACY<<8 | 13)
	R14L Reg = Reg(4<<16 | REG_LEGACY<<8 | 14)
	R15L Reg = Reg(4<<16 | REG_LEGACY<<8 | 15)

	// 64-bit
	RAX Reg = Reg(8<<16 | REG_LEGACY<<8 | 0)
	RCX Reg = Reg(8<<16 | REG_LEGACY<<8 | 1)
	RDX Reg = Reg(8<<16 | REG_LEGACY<<8 | 2)
	RBX Reg = Reg(8<<16 | REG_LEGACY<<8 | 3)
	RSP Reg = Reg(8<<16 | REG_LEGACY<<8 | 4)
	RBP Reg = Reg(8<<16 | REG_LEGACY<<8 | 5)
	RSI Reg = Reg(8<<16 | REG_LEGACY<<8 | 6)
	RDI Reg = Reg(8<<16 | REG_LEGACY<<8 | 7)
	R8  Reg = Reg(8<<16 | REG_LEGACY<<8 | 8)
	R9  Reg = Reg(8<<16 | REG_LEGACY<<8 | 9)
	R10 Reg = Reg(8<<16 | REG_LEGACY<<8 | 10)
	R11 Reg = Reg(8<<16 | REG_LEGACY<<8 | 11)
	R12 Reg = Reg(8<<16 | REG_LEGACY<<8 | 12)
	R13 Reg = Reg(8<<16 | REG_LEGACY<<8 | 13)
	R14 Reg = Reg(8<<16 | REG_LEGACY<<8 | 14)
	R15 Reg = Reg(8<<16 | REG_LEGACY<<8 | 15)

	// Instruction pointer.
	IP  Reg = Reg(2<<16 | REG_RIP<<8 | 0) // 16-bit
	EIP Reg = Reg(4<<16 | REG_RIP<<8 | 0) // 32-bit
	RIP Reg = Reg(8<<16 | REG_RIP<<8 | 0) // 64-bit

	// 387 floating point registers.
	F0 Reg = Reg(10<<16 | REG_FP<<8 | 0)
	F1 Reg = Reg(10<<16 | REG_FP<<8 | 1)
	F2 Reg = Reg(10<<16 | REG_FP<<8 | 2)
	F3 Reg = Reg(10<<16 | REG_FP<<8 | 3)
	F4 Reg = Reg(10<<16 | REG_FP<<8 | 4)
	F5 Reg = Reg(10<<16 | REG_FP<<8 | 5)
	F6 Reg = Reg(10<<16 | REG_FP<<8 | 6)
	F7 Reg = Reg(10<<16 | REG_FP<<8 | 7)

	// MMX registers.
	M0 Reg = Reg(8<<16 | REG_MMX<<8 | 0)
	M1 Reg = Reg(8<<16 | REG_MMX<<8 | 1)
	M2 Reg = Reg(8<<16 | REG_MMX<<8 | 2)
	M3 Reg = Reg(8<<16 | REG_MMX<<8 | 3)
	M4 Reg = Reg(8<<16 | REG_MMX<<8 | 4)
	M5 Reg = Reg(8<<16 | REG_MMX<<8 | 5)
	M6 Reg = Reg(8<<16 | REG_MMX<<8 | 6)
	M7 Reg = Reg(8<<16 | REG_MMX<<8 | 7)

	// XMM registers.
	X0  Reg = Reg(16<<16 | REG_XMM<<8 | 0)
	X1  Reg = Reg(16<<16 | REG_XMM<<8 | 1)
	X2  Reg = Reg(16<<16 | REG_XMM<<8 | 2)
	X3  Reg = Reg(16<<16 | REG_XMM<<8 | 3)
	X4  Reg = Reg(16<<16 | REG_XMM<<8 | 4)
	X5  Reg = Reg(16<<16 | REG_XMM<<8 | 5)
	X6  Reg = Reg(16<<16 | REG_XMM<<8 | 6)
	X7  Reg = Reg(16<<16 | REG_XMM<<8 | 7)
	X8  Reg = Reg(16<<16 | REG_XMM<<8 | 8)
	X9  Reg = Reg(16<<16 | REG_XMM<<8 | 9)
	X10 Reg = Reg(16<<16 | REG_XMM<<8 | 10)
	X11 Reg = Reg(16<<16 | REG_XMM<<8 | 11)
	X12 Reg = Reg(16<<16 | REG_XMM<<8 | 12)
	X13 Reg = Reg(16<<16 | REG_XMM<<8 | 13)
	X14 Reg = Reg(16<<16 | REG_XMM<<8 | 14)
	X15 Reg = Reg(16<<16 | REG_XMM<<8 | 15)

	// YMM registers.
	Y0  Reg = Reg(32<<16 | REG_YMM<<8 | 0)
	Y1  Reg = Reg(32<<16 | REG_YMM<<8 | 1)
	Y2  Reg = Reg(32<<16 | REG_YMM<<8 | 2)
	Y3  Reg = Reg(32<<16 | REG_YMM<<8 | 3)
	Y4  Reg = Reg(32<<16 | REG_YMM<<8 | 4)
	Y5  Reg = Reg(32<<16 | REG_YMM<<8 | 5)
	Y6  Reg = Reg(32<<16 | REG_YMM<<8 | 6)
	Y7  Reg = Reg(32<<16 | REG_YMM<<8 | 7)
	Y8  Reg = Reg(32<<16 | REG_YMM<<8 | 8)
	Y9  Reg = Reg(32<<16 | REG_YMM<<8 | 9)
	Y10 Reg = Reg(32<<16 | REG_YMM<<8 | 10)
	Y11 Reg = Reg(32<<16 | REG_YMM<<8 | 11)
	Y12 Reg = Reg(32<<16 | REG_YMM<<8 | 12)
	Y13 Reg = Reg(32<<16 | REG_YMM<<8 | 13)
	Y14 Reg = Reg(32<<16 | REG_YMM<<8 | 14)
	Y15 Reg = Reg(32<<16 | REG_YMM<<8 | 15)

	// Segment registers.
	ES Reg = Reg(2<<16 | REG_SEGMENT<<8 | 0)
	CS Reg = Reg(2<<16 | REG_SEGMENT<<8 | 1)
	SS Reg = Reg(2<<16 | REG_SEGMENT<<8 | 2)
	DS Reg = Reg(2<<16 | REG_SEGMENT<<8 | 3)
	FS Reg = Reg(2<<16 | REG_SEGMENT<<8 | 4)
	GS Reg = Reg(2<<16 | REG_SEGMENT<<8 | 5)

	// Control registers.
	CR0  Reg = Reg(4<<16 | REG_CONTROL<<8 | 0)
	CR1  Reg = Reg(4<<16 | REG_CONTROL<<8 | 1)
	CR2  Reg = Reg(4<<16 | REG_CONTROL<<8 | 2)
	CR3  Reg = Reg(4<<16 | REG_CONTROL<<8 | 3)
	CR4  Reg = Reg(4<<16 | REG_CONTROL<<8 | 4)
	CR5  Reg = Reg(4<<16 | REG_CONTROL<<8 | 5)
	CR6  Reg = Reg(4<<16 | REG_CONTROL<<8 | 6)
	CR7  Reg = Reg(4<<16 | REG_CONTROL<<8 | 7)
	CR8  Reg = Reg(4<<16 | REG_CONTROL<<8 | 8)
	CR9  Reg = Reg(4<<16 | REG_CONTROL<<8 | 9)
	CR10 Reg = Reg(4<<16 | REG_CONTROL<<8 | 10)
	CR11 Reg = Reg(4<<16 | REG_CONTROL<<8 | 11)
	CR12 Reg = Reg(4<<16 | REG_CONTROL<<8 | 12)
	CR13 Reg = Reg(4<<16 | REG_CONTROL<<8 | 13)
	CR14 Reg = Reg(4<<16 | REG_CONTROL<<8 | 14)
	CR15 Reg = Reg(4<<16 | REG_CONTROL<<8 | 15)

	// Debug registers.
	DR0  Reg = Reg(4<<16 | REG_DEBUG<<8 | 0)
	DR1  Reg = Reg(4<<16 | REG_DEBUG<<8 | 1)
	DR2  Reg = Reg(4<<16 | REG_DEBUG<<8 | 2)
	DR3  Reg = Reg(4<<16 | REG_DEBUG<<8 | 3)
	DR4  Reg = Reg(4<<16 | REG_DEBUG<<8 | 4)
	DR5  Reg = Reg(4<<16 | REG_DEBUG<<8 | 5)
	DR6  Reg = Reg(4<<16 | REG_DEBUG<<8 | 6)
	DR7  Reg = Reg(4<<16 | REG_DEBUG<<8 | 7)
	DR8  Reg = Reg(4<<16 | REG_DEBUG<<8 | 8)
	DR9  Reg = Reg(4<<16 | REG_DEBUG<<8 | 9)
	DR10 Reg = Reg(4<<16 | REG_DEBUG<<8 | 10)
	DR11 Reg = Reg(4<<16 | REG_DEBUG<<8 | 11)
	DR12 Reg = Reg(4<<16 | REG_DEBUG<<8 | 12)
	DR13 Reg = Reg(4<<16 | REG_DEBUG<<8 | 13)
	DR14 Reg = Reg(4<<16 | REG_DEBUG<<8 | 14)
	DR15 Reg = Reg(4<<16 | REG_DEBUG<<8 | 15)
)
