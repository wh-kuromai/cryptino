package cryptino

import (
	"crypto"
	"crypto/elliptic"
)

type CipherSuite struct {
	Name        string
	KeyType     string
	Bit         int
	Padding     string
	Curve       elliptic.Curve
	Hash        crypto.Hash
	GenerateKey func(cs *CipherSuite) (PrivateKey, error)
}

func (cs *CipherSuite) HashEncode(msg []byte) []byte {
	h := crypto.Hash.New(cs.Hash)
	h.Write(([]byte)(msg))
	return h.Sum(nil)
}

func generateRSAKeyPK(cs *CipherSuite) (PrivateKey, error) {
	return GenerateRSAKey(cs)
}

func generateECKeyPK(cs *CipherSuite) (PrivateKey, error) {
	return GenerateECKey(cs)
}

var (
	rs256T = CipherSuite{
		Name:        "RS256",
		KeyType:     "RSA",
		Padding:     "PKCS1",
		Bit:         2048,
		Hash:        crypto.SHA256,
		GenerateKey: generateRSAKeyPK,
	}
	rs384T = CipherSuite{
		Name:        "RS384",
		KeyType:     "RSA",
		Padding:     "PKCS1",
		Bit:         3072,
		Hash:        crypto.SHA384,
		GenerateKey: generateRSAKeyPK,
	}
	rs512T = CipherSuite{
		Name:        "RS512",
		KeyType:     "RSA",
		Padding:     "PKCS1",
		Bit:         4096,
		Hash:        crypto.SHA512,
		GenerateKey: generateRSAKeyPK,
	}
	ps256T = CipherSuite{
		Name:        "PS256",
		KeyType:     "RSA",
		Bit:         2048,
		Hash:        crypto.SHA256,
		GenerateKey: generateRSAKeyPK,
	}
	ps384T = CipherSuite{
		Name:        "PS384",
		KeyType:     "RSA",
		Bit:         3072,
		Hash:        crypto.SHA384,
		GenerateKey: generateRSAKeyPK,
	}
	ps512T = CipherSuite{
		Name:        "PS512",
		KeyType:     "RSA",
		Bit:         4096,
		Hash:        crypto.SHA512,
		GenerateKey: generateRSAKeyPK,
	}
	es256T = CipherSuite{
		Name:        "ES256",
		KeyType:     "ECDSA",
		Curve:       elliptic.P256(),
		Hash:        crypto.SHA256,
		GenerateKey: generateECKeyPK,
	}
	es384T = CipherSuite{
		Name:        "ES384",
		KeyType:     "ECDSA",
		Curve:       elliptic.P384(),
		Hash:        crypto.SHA384,
		GenerateKey: generateECKeyPK,
	}
	es512T = CipherSuite{
		Name:        "ES512",
		KeyType:     "ECDSA",
		Curve:       elliptic.P521(),
		Hash:        crypto.SHA512,
		GenerateKey: generateECKeyPK,
	}

	sha256T = CipherSuite{
		Hash: crypto.SHA256,
	}
	sha384T = CipherSuite{
		Hash: crypto.SHA384,
	}
	sha512T = CipherSuite{
		Hash: crypto.SHA512,
	}
)

func RS256() *CipherSuite  { cs := rs256T; return &cs }
func RS384() *CipherSuite  { cs := rs384T; return &cs }
func RS512() *CipherSuite  { cs := rs512T; return &cs }
func PS256() *CipherSuite  { cs := ps256T; return &cs }
func PS384() *CipherSuite  { cs := ps384T; return &cs }
func PS512() *CipherSuite  { cs := ps512T; return &cs }
func ES256() *CipherSuite  { cs := es256T; return &cs }
func ES384() *CipherSuite  { cs := es384T; return &cs }
func ES512() *CipherSuite  { cs := es512T; return &cs }
func SHA256() *CipherSuite { cs := sha256T; return &cs }
func SHA384() *CipherSuite { cs := sha384T; return &cs }
func SHA512() *CipherSuite { cs := sha512T; return &cs }

func GetCipherSuiteFromAlg(alg string) *CipherSuite {
	switch alg {
	case "RS256":
		return RS256()
	case "RS384":
		return RS384()
	case "RS512":
		return RS512()
	case "ES256":
		return ES256()
	case "ES384":
		return ES384()
	case "ES512":
		return ES512()
	}
	return nil
}
