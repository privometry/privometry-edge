package contract

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewID returns a prefixed ULID such as evt_01JAB7Q8XK3M2N4P5R6S7T8V9W: a
// 48-bit millisecond timestamp and 80 random bits in Crockford base32, so IDs
// sort by creation time.
func NewID(prefix string) string { return prefix + "_" + ULID(time.Now()) }

// ULID encodes t and 80 random bits as a 26-character ULID.
func ULID(t time.Time) string {
	var b [16]byte
	ms := uint64(max(t.UnixMilli(), 0))                //nolint:gosec // clamped: ULIDs cannot encode times before 1970
	binary.BigEndian.PutUint16(b[0:2], uint16(ms>>32)) //nolint:gosec // deliberate: the top 16 bits of the 48-bit timestamp
	binary.BigEndian.PutUint32(b[2:6], uint32(ms))     //nolint:gosec // deliberate: the low 32 bits of the 48-bit timestamp
	if _, err := rand.Read(b[6:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	// 128 bits into 26 characters of 5 bits; the first character carries 3 bits.
	var out [26]byte
	hi := binary.BigEndian.Uint64(b[0:8])
	lo := binary.BigEndian.Uint64(b[8:16])
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:])
}
