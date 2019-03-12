// package stacks provides tracking for allocations, deallocations, and uses of stack-slots while assembling a function
package stacks

import (
	"math/bits"
)

// Stack tracks allocations, deallocations, and uses of stack-slots while assembling a function.
//
// Stack-slots may have a size of 8, 16, 32, 64, 128, 256, 512, or 1024 bytes.
type Stack struct {
	sizes [8]fixedPool
}

// StackSlot references a virtual stack-slot allocation for a given slot-size.
type StackSlot struct {
	// The size in bytes of the virtual stack-slot
	Size int
	// The slot-number of the virtual stack-slot
	Slot int
}

// StackSlot references a virtual stack-slot allocation for a given slot-size.
type StackSlotOffset struct {
	// The size in bytes of the virtual stack-slot
	Size int
	// The slot-number of the virtual stack-slot
	Slot int
	// The byte-offset for the the virtual stack-slot relative to the beginning of the stack.
	Offset int
}

// Stack tracks allocations, deallocations, and uses of stack-slots for an assembled function.
//
// Stack-slots may have a size of 8, 16, 32, 64, 128, 256, 512, or 1024 bytes.
func NewStack() *Stack {
	s := &Stack{}
	s.Reset()
	return s
}

// Get the total size in bytes required to contain all stack-slot allocations since the stack
// was last reset.
func (s *Stack) TotalSize() int {
	sz := 0
	for i := range s.sizes {
		sz += len(s.sizes[i].slots) * (1 << (3 + uint(i)))
	}
	return sz
}

// Get the total number of stack-slots for the given size required to contain all allocations
// sinze the stack was last reset.
func (s *Stack) TotalSlots(size int) int { return len(s.sizes[poolOffset(size)].slots) }

// Finalize all stack-slot mappings and return an arranged set of stack-slot entries with offsets
// relative to the beginning of the stack. Entries will be ordered by size, with larger entries at
// the beginning of the stack.
func (s *Stack) Finalize() []StackSlotOffset {
	off := 0
	nslots := 0
	for _, pool := range s.sizes {
		nslots += len(pool.slots)
	}
	finalized := make([]StackSlotOffset, 0, nslots)
	for i := len(s.sizes) - 1; i >= 0; i-- {
		size := (1 << (3 + uint(i)))
		for j := range s.sizes[i].slots {
			finalized = append(finalized, StackSlotOffset{Size: size, Slot: j, Offset: off})
			off += size
		}
	}
	return finalized
}

// Clear and reset all stack-slot entries.
func (s *Stack) Reset() {
	for i := range s.sizes {
		s.sizes[i].reset()
	}
}

// Allocate a stack-slot with the given size in bytes. The allocated slot-number will be returned.
// Slot-numbers are distinct for each size, but may be shared across different sizes.
//
// size must be 8, 16, 32, 64, 128, 256, 512, or 1024.
func (s *Stack) Alloc(size int) StackSlot {
	pool := &s.sizes[poolOffset(size)]
	for i, used := range pool.slots {
		if !used {
			pool.slots[i] = true
			return StackSlot{Size: size, Slot: i}
		}
	}
	pool.slots = append(pool.slots, true)
	return StackSlot{Size: size, Slot: len(pool.slots) - 1}
}

// Free an allocated stack-slot. The slot must be allocated through a call to Alloc before it may be freed.
// After the stack-slot is freed, it may be filled by a future call to Alloc with a matching size.
func (s *Stack) Free(slot StackSlot) { s.sizes[poolOffset(slot.Size)].slots[slot.Slot] = false }

// Convert a stack-slot with an offset to a stack-slot without an offset. This can be helpful when
// mapping finalized slots back to slots which were created while assembling a function.
func (ss *StackSlotOffset) StackSlot() StackSlot { return StackSlot{Size: ss.Size, Slot: ss.Slot} }

func poolOffset(size int) int { return bits.TrailingZeros(uint(size >> 3)) }

type fixedPool struct {
	// using bit-vectors would be more efficient, but whatever
	slots  []bool
	_slots [40]bool // hopefully align to a cache-line
}

func (p *fixedPool) reset() { p.slots = p._slots[:0] }
