package cryptino

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"strings"
)

type Hash func(msg []byte) []byte

func SHA(alg crypto.Hash) func(msg []byte) []byte {
	return func(msg []byte) []byte {
		h := crypto.Hash.New(alg)
		h.Write(([]byte)(msg))
		return h.Sum(nil)
	}
}

func HashFromSuiteString(alg string) Hash {
	if strings.Contains(alg, "SHA256") {
		return SHA256
	} else if strings.Contains(alg, "SHA386") {
		return SHA384
	} else if strings.Contains(alg, "SHA512") {
		return SHA512
	}

	return SHA256
}

func hashFromSize(size int) crypto.Hash {
	switch size {
	case 256:
		return crypto.SHA256
	case 384:
		return crypto.SHA384
	case 521:
		return crypto.SHA512
	}
	return crypto.SHA256
}

func hashAlgFromSize(size int) Hash {
	switch size {
	case 256:
		return SHA256
	case 384:
		return SHA384
	case 521:
		return SHA512
	}
	return SHA256
}

func SHA256Reader(r io.Reader) ([]byte, io.Reader, error) {
	if r == nil {
		return nil, r, nil
	}

	buf := &bytes.Buffer{}
	tee := io.TeeReader(r, buf)
	h := crypto.Hash.New(crypto.SHA256)
	written, err := io.Copy(h, tee)
	if err != nil {
		return nil, nil, err
	}
	if written > 0 {
		return h.Sum(nil), buf, nil

	}

	return nil, buf, nil
}

type Sharedkey struct {
	Secret []byte
	S      int
}

func NewSharedKey(alg string, secret []byte) *Sharedkey {
	h := &Sharedkey{}
	h.Secret = HashFromSuiteString(alg)(secret)
	h.S = len(h.Secret) * 8
	return h
}

func (h *Sharedkey) Name() string {
	return "HMAC"
}

func (h *Sharedkey) Size() int {
	return h.S
}

func (h *Sharedkey) Encrypt(alg string, secretstr []byte, msg []byte) ([]byte, error) {
	return EncryptByGCM(h.Secret, msg)
}

func (h *Sharedkey) Decrypt(alg string, secretstr []byte, msg []byte) ([]byte, error) {
	return DecryptByGCM(h.Secret, msg)
}

func (h *Sharedkey) Verify(alg string, msg []byte, sign []byte) bool {
	hmacSign, _ := h.Signature(alg, msg)
	return hmac.Equal(hmacSign, sign)
}

func (h *Sharedkey) Signature(alg string, msg []byte) ([]byte, error) {
	hmac := hmac.New(sha256.New, h.Secret)
	hmac.Write([]byte(msg))
	dataHmac := hmac.Sum(nil)
	return dataHmac, nil
}
