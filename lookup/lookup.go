package x64lookup

import (
	"github.com/wdamron/x64"
)

const maxMnemonicLength = 16

// Lookup the instruction for a mnemonic. The mnemonic will be converted to uppercase if necessary.
func Inst(mnemonic string) (x64.Inst, bool) {
	if len(mnemonic) < maxMnemonicLength {
		inst, ok := instMap[upperCase(mnemonic)]
		return inst, ok
	}
	return x64.Inst(0), false
}

func upperCase(s string) string {
	var b [maxMnemonicLength]byte
	var ch byte
	_ = b[len(s)] // lift bounds-checks out of the loop below (golang.org/issue/14808)
	i, changed := 0, false
loop: // functions containing for-loops cannot currently be inlined (golang.org/issue/14768)
	ch = s[i]
	b[i] = ch &^ ((ch & 0x40) >> 1)
	changed = changed || b[i] != ch
	i++
	if i < len(s) {
		goto loop
	}
	if !changed {
		return s
	}
	return string(b[:len(s)])
}
