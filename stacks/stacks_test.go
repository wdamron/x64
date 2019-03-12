package stacks

import (
	"testing"
)

func TestStack(t *testing.T) {
	s := NewStack()

	x8 := s.Alloc(8)
	y8 := s.Alloc(8)
	s.Free(x8)
	z8 := s.Alloc(8)
	s.Free(y8)
	s.Free(z8)

	if s.TotalSize() != 16 {
		t.Fatalf("Expected total size of 16 bytes, found %v", s.TotalSize())
	}
	if s.TotalSlots(8) != 2 {
		t.Fatalf("Expected 2 total 8-byte slots, found %v", s.TotalSlots(8))
	}

	x16 := s.Alloc(16)
	y16 := s.Alloc(16)
	s.Free(x16)
	z16 := s.Alloc(16)
	s.Free(y16)
	s.Free(z16)

	if s.TotalSize() != 16+32 {
		t.Fatalf("Expected total size of 16+32 bytes, found %v", s.TotalSize())
	}
	if s.TotalSlots(16) != 2 {
		t.Fatalf("Expected 2 total 16-byte slots, found %v", s.TotalSlots(16))
	}

	_ = s.Alloc(1024)
	if s.TotalSize() != 16+32+1024 {
		t.Fatalf("Expected total size of 16+32+1024 bytes, found %v", s.TotalSize())
	}
	if s.TotalSlots(1024) != 1 {
		t.Fatalf("Expected 1 total 1024-byte slot, found %v", s.TotalSlots(1024))
	}

	fin := s.Finalize()
	if len(fin) != 5 {
		t.Fatalf("Expected 5 total slots")
	}
	if fin[0].Size != 1024 || fin[0].Slot != 0 || fin[0].Offset != 0 {
		t.Fatalf("finalized[0] = %#v", fin[0])
	}
	if fin[1].Size != 16 || fin[1].Slot != 0 || fin[1].Offset != 1024 {
		t.Fatalf("finalized[1] = %#v", fin[1])
	}
	if fin[2].Size != 16 || fin[2].Slot != 1 || fin[2].Offset != 1024+16 {
		t.Fatalf("finalized[2] = %#v", fin[2])
	}
	if fin[3].Size != 8 || fin[3].Slot != 0 || fin[3].Offset != 1024+16+16 {
		t.Fatalf("finalized[3] = %#v", fin[3])
	}
	if fin[4].Size != 8 || fin[4].Slot != 1 || fin[4].Offset != 1024+16+16+8 {
		t.Fatalf("finalized[4] = %#v", fin[4])
	}

	s.Reset()
	if s.TotalSize() != 0 {
		t.Fatalf("Expected total size of 0 bytes after reset, found %v", s.TotalSize())
	}
	if s.TotalSlots(8) != 0 {
		t.Fatalf("Expected 0 total 8-byte slots after reset, found %v", s.TotalSlots(8))
	}
	if s.TotalSlots(16) != 0 {
		t.Fatalf("Expected 0 total 16-byte slots after reset, found %v", s.TotalSlots(16))
	}
	if s.TotalSlots(1024) != 0 {
		t.Fatalf("Expected 0 total 1024-byte slots after reset, found %v", s.TotalSlots(1024))
	}
}
