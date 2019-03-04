package x64

import (
	"encoding/binary"
)

type buffer struct {
	b  []byte
	i  int
	sz int
}

func newBuffer(b []byte) *buffer {
	return &buffer{b, 0, len(b)}
}

func (b *buffer) extend(length int) {
	if len(b.b)-b.i >= length {
		return
	}
	bb := make([]byte, len(b.b)*2)
	copy(bb, b.b[:b.i])
	b.b = bb
}

func (b *buffer) Len() int    { return b.i }
func (b *buffer) Cap() int    { return len(b.b) }
func (b *buffer) Get() []byte { return b.b[:b.i] }
func (b *buffer) Reset()      { b.ResizeReset(b.sz) }
func (b *buffer) ResizeReset(capacity int) {
	if len(b.b) != capacity {
		b.b = make([]byte, capacity)
	}
	b.i = 0
}

func (b *buffer) Byte(v byte) {
	b.extend(1)
	b.b[b.i] = v
	b.i++
}

func (b *buffer) Byte2(v1, v2 byte) {
	b.extend(2)
	b.b[b.i], b.b[b.i+1] = v1, v2
	b.i += 2
}

func (b *buffer) Bytes(v []byte) {
	b.extend(len(v))
	copy(b.b[b.i:], v)
	b.i += len(v)
}

func (b *buffer) Int8(v int8) {
	b.extend(1)
	b.Byte(byte(v))
}

func (b *buffer) Int16(v int16) {
	b.extend(2)
	binary.LittleEndian.PutUint16(b.b[b.i:], uint16(v))
	b.i += 2
}

func (b *buffer) Int32(v int32) {
	b.extend(4)
	binary.LittleEndian.PutUint32(b.b[b.i:], uint32(v))
	b.i += 4
}

func (b *buffer) Int64(v int64) {
	b.extend(8)
	binary.LittleEndian.PutUint64(b.b[b.i:], uint64(v))
	b.i += 8
}

func (b *buffer) Nop(length uint8) {
	maxNop := uint8(len(nops))
	for length > 0 {
		if length > maxNop {
			b.Bytes(nops[maxNop-1][:maxNop])
			length -= maxNop
		} else {
			b.Bytes(nops[length-1][:length])
			break
		}
	}
}
