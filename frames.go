package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/crypto/hkdf"
)

const (
	clientFrameHeaderLen = 37
	adminFrameHeaderLen  = 28
	frameVersionPlain    = 0x01
	frameVersionEnc      = 0x02
	hkdfInfo             = "decoder-client-v1-stream-key"
)

var frameDecryptKey []byte // nil = encryption not configured

func initFrameCrypto() {
	// Match client derive_session_key_from_env: HKDF-SHA256 over server cert pin.
	seed := os.Getenv("DECODER_FRAME_KEY")
	if seed == "" {
		return
	}
	h := hkdf.New(sha256.New, []byte(seed), nil, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := h.Read(key); err != nil {
		return
	}
	frameDecryptKey = key
}

// normalizeClientFrame converts agent v1 wire format to the legacy 28-byte admin
// header + plain JPEG that the dashboard renderer expects.
func normalizeClientFrame(data []byte) ([]byte, error) {
	if len(data) < clientFrameHeaderLen {
		if len(data) >= adminFrameHeaderLen {
			return data, nil
		}
		return nil, fmt.Errorf("frame too short (%d bytes)", len(data))
	}

	version := data[0]
	if version != frameVersionPlain && version != frameVersionEnc {
		return data, nil
	}

	w := binary.LittleEndian.Uint32(data[9:13])
	h := binary.LittleEndian.Uint32(data[13:17])
	ts := binary.LittleEndian.Uint64(data[17:25])
	mon := binary.LittleEndian.Uint32(data[25:29])
	cx := int32(binary.LittleEndian.Uint32(data[29:33]))
	cy := int32(binary.LittleEndian.Uint32(data[33:37]))

	var jpeg []byte
	var err error
	if version == frameVersionEnc {
		if frameDecryptKey == nil {
			return nil, fmt.Errorf("encrypted frame but DECODER_FRAME_KEY not set")
		}
		seq := binary.LittleEndian.Uint64(data[1:9])
		jpeg, err = decryptFramePayload(frameDecryptKey, seq, data[clientFrameHeaderLen:])
		if err != nil {
			return nil, err
		}
	} else {
		jpeg = data[clientFrameHeaderLen:]
	}

	out := make([]byte, adminFrameHeaderLen+len(jpeg))
	binary.LittleEndian.PutUint32(out[0:4], w)
	binary.LittleEndian.PutUint32(out[4:8], h)
	binary.LittleEndian.PutUint64(out[8:16], ts)
	binary.LittleEndian.PutUint32(out[16:20], mon)
	binary.LittleEndian.PutUint32(out[20:24], uint32(cx))
	binary.LittleEndian.PutUint32(out[24:28], uint32(cy))
	copy(out[adminFrameHeaderLen:], jpeg)
	return out, nil
}

func decryptFramePayload(key []byte, seq uint64, data []byte) ([]byte, error) {
	if len(data) < 12+16 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := data[:12]
	ciphertext := data[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := make([]byte, 8)
	binary.LittleEndian.PutUint64(aad, seq)
	plain, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("GCM auth failed: %w", err)
	}
	return plain, nil
}
