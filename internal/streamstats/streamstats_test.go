package streamstats

import (
	"encoding/binary"
	"testing"
)

func buildV1Frame(seq uint64, w, h, mon uint32, tsUs uint64, payloadLen int) []byte {
	buf := make([]byte, clientHeaderLen+payloadLen)
	buf[0] = frameVersionPlain
	binary.LittleEndian.PutUint64(buf[1:9], seq)
	binary.LittleEndian.PutUint32(buf[9:13], w)
	binary.LittleEndian.PutUint32(buf[13:17], h)
	binary.LittleEndian.PutUint64(buf[17:25], tsUs)
	binary.LittleEndian.PutUint32(buf[25:29], mon)
	return buf
}

func TestParseHeaderAndDroppedFrames(t *testing.T) {
	reg := NewRegistry()
	reg.Record("c1", buildV1Frame(0, 1920, 1080, 0, 1_000_000, 1000))
	reg.Record("c1", buildV1Frame(3, 1920, 1080, 0, 2_000_000, 1000)) // gap 1,2

	snap, ok := reg.Snapshot("c1")
	if !ok {
		t.Fatal("expected snapshot")
	}
	if snap.DroppedFrames != 2 {
		t.Fatalf("dropped = %d, want 2", snap.DroppedFrames)
	}
	if snap.Resolution != "1920x1080" {
		t.Fatalf("resolution = %q", snap.Resolution)
	}
}
