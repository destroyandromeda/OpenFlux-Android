package yandex

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func TestDecodeSequencedBatch(t *testing.T) {
	blob := append([]byte(nil), sequencedBatchMagic[:]...)
	header := make([]byte, 16)
	binary.BigEndian.PutUint64(header[:8], 42)
	binary.BigEndian.PutUint64(header[8:], 7)
	blob = append(blob, header...)
	for _, packet := range [][]byte{[]byte("one"), []byte("two")} {
		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, uint16(len(packet)))
		blob = append(blob, length...)
		blob = append(blob, packet...)
	}

	epoch, sequence, packets, ok := decodeSequencedBatch(blob)
	if !ok || epoch != 42 || sequence != 7 {
		t.Fatalf("unexpected envelope: ok=%v epoch=%d sequence=%d", ok, epoch, sequence)
	}
	if !reflect.DeepEqual(packets, [][]byte{[]byte("one"), []byte("two")}) {
		t.Fatalf("unexpected packets: %q", packets)
	}
}

func TestSequencedBatchReordersAndDeduplicates(t *testing.T) {
	var delivered []string
	w := &wsListener{
		stats:          &VolgaStats{},
		pendingBatches: make(map[uint64][][]byte),
		retiredEpochs:  make(map[uint64]struct{}),
		onData: func(packet []byte) {
			delivered = append(delivered, string(packet))
		},
	}

	w.handleSequencedBatch(10, 1, [][]byte{[]byte("one")})
	w.handleSequencedBatch(10, 3, [][]byte{[]byte("three")})
	w.handleSequencedBatch(10, 2, [][]byte{[]byte("two")})
	w.handleSequencedBatch(10, 2, [][]byte{[]byte("duplicate")})

	if !reflect.DeepEqual(delivered, []string{"one", "two", "three"}) {
		t.Fatalf("unexpected delivery order: %v", delivered)
	}
}

func TestSequencedBatchCanJoinMidstream(t *testing.T) {
	var delivered []string
	w := &wsListener{
		stats:          &VolgaStats{},
		pendingBatches: make(map[uint64][][]byte),
		retiredEpochs:  make(map[uint64]struct{}),
		onData: func(packet []byte) {
			delivered = append(delivered, string(packet))
		},
	}

	w.handleSequencedBatch(20, 5, [][]byte{[]byte("five")})
	w.flushSequenceGap(20)

	if !reflect.DeepEqual(delivered, []string{"five"}) {
		t.Fatalf("midstream batch was not released: %v", delivered)
	}
}
