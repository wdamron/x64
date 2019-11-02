package feats

type Feature uint32

// CPU Features
const (
	X64_IMPLICIT Feature = 0
	FPU          Feature = 1 << iota
	MMX
	TDNOW
	SSE
	SSE2
	SSE3
	VMX
	SSSE3
	SSE4A
	SSE41
	SSE42
	SSE5
	AVX
	AVX2
	FMA
	BMI1
	BMI2
	TBM
	RTM
	INVPCID
	MPX
	SHA
	PREFETCHWT1
	// Cyrix instructions are omitted
	CYRIX
	AMD
)

const AllFeatures Feature = 0xffffffff

func FeatName(f Feature) string { return featNames[f] }

var featNames = map[Feature]string{
	X64_IMPLICIT: "X64_IMPLICIT",
	FPU:          "FPU",
	MMX:          "MMX",
	TDNOW:        "TDNOW",
	SSE:          "SSE",
	SSE2:         "SSE2",
	SSE3:         "SSE3",
	VMX:          "VMX",
	SSSE3:        "SSSE3",
	SSE4A:        "SSE4A",
	SSE41:        "SSE41",
	SSE42:        "SSE42",
	SSE5:         "SSE5",
	AVX:          "AVX",
	AVX2:         "AVX2",
	FMA:          "FMA",
	BMI1:         "BMI1",
	BMI2:         "BMI2",
	TBM:          "TBM",
	RTM:          "RTM",
	INVPCID:      "INVPCID",
	MPX:          "MPX",
	SHA:          "SHA",
	PREFETCHWT1:  "PREFETCHWT1",
	CYRIX:        "CYRIX",
	AMD:          "AMD",
}
