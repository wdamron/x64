package x64lookup

import (
	"testing"
)

func TestLookup(t *testing.T) {
	_, ok := Inst("mov")
	if !ok {
		t.Fatal("failed to find mov")
	}
	_, ok = Inst("MOV")
	if !ok {
		t.Fatal("failed to find MOV")
	}
}
