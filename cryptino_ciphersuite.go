package cryptino

import (
	"crypto"
	"crypto/elliptic"
)

var SHA256 = SHA(crypto.SHA256)
var SHA384 = SHA(crypto.SHA384)
var SHA512 = SHA(crypto.SHA512)

var DEFAULT = GetCipherSuiteFromAlg("DEFAULT")

type CipherSuite struct {
	Name        string
	KeyType     string
	Bit         int
	Padding     string
	Curve       elliptic.Curve
	Hash        Hash
	GenerateKey func(cs *CipherSuite) (PrivateKey, error)
}

func generateRSAKeyPK(cs *CipherSuite) (PrivateKey, error) {
	return GenerateRSAKey(cs)
}

func generateECKeyPK(cs *CipherSuite) (PrivateKey, error) {
	return GenerateECKey(cs)
}

func GetCipherSuiteFromAlg(alg string) *CipherSuite {
	switch alg {
	case "RS256":
		return &CipherSuite{
			Name:        "RS256",
			KeyType:     "RSA",
			Bit:         2048,
			Hash:        SHA256,
			GenerateKey: generateRSAKeyPK,
		}
	case "RS384":
		return &CipherSuite{
			Name:        "RS256",
			KeyType:     "RSA",
			Bit:         3072,
			Hash:        SHA384,
			GenerateKey: generateRSAKeyPK,
		}
	case "RS512":
		return &CipherSuite{
			Name:        "RS512",
			KeyType:     "RSA",
			Bit:         4096,
			Hash:        SHA512,
			GenerateKey: generateRSAKeyPK,
		}
	case "ES256":
		return &CipherSuite{
			Name:        "ES256",
			KeyType:     "EC",
			Curve:       elliptic.P256(),
			Hash:        SHA256,
			GenerateKey: generateECKeyPK,
		}
	case "ES384":
		return &CipherSuite{
			Name:        "ES384",
			KeyType:     "EC",
			Curve:       elliptic.P384(),
			Hash:        SHA384,
			GenerateKey: generateECKeyPK,
		}
	case "ES512":
		return &CipherSuite{
			Name:        "ES512",
			KeyType:     "EC",
			Curve:       elliptic.P521(),
			Hash:        SHA512,
			GenerateKey: generateECKeyPK,
		}
	case "DEFAULT":
		return &CipherSuite{
			Bit:         2048,
			Curve:       elliptic.P256(),
			Hash:        SHA512,
			GenerateKey: generateECKeyPK,
		}
	}
	return nil
}
