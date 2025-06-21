package cryptino

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/ssh"
)

// PublicKey object.
type PublicKey interface {
	Name() string
	Size() int
	MarshalJSON() ([]byte, error)
	MarshalSSHWire() []byte
	Verify(cs *CipherSuite, msg []byte, sign []byte) bool
	Thumbprint(cs *CipherSuite) string
}

// PrivateKey object. This object includes public key inside.
type PrivateKey interface {
	Name() string
	Size() int
	MarshalJSON() ([]byte, error)
	Public() PublicKey
	Signature(cs *CipherSuite, msg []byte) ([]byte, error)
	Encrypt(cs *CipherSuite, remote PublicKey, msg []byte) ([]byte, error)
	Decrypt(cs *CipherSuite, remote PublicKey, msg []byte) ([]byte, error)
}

type Verifier interface {
	Name() string
	Size() int
	Verify(cs *CipherSuite, msg []byte, sign []byte) bool
}

type Signer interface {
	Name() string
	Size() int
	Signature(cs *CipherSuite, msg []byte) ([]byte, error)
}

// GenerateKey create ney key with speficied algorism.
func GenerateKey(alg string) (PrivateKey, error) {
	cs := GetCipherSuiteFromAlg(alg)
	if cs.GenerateKey != nil {
		return cs.GenerateKey(cs)
	}

	return nil, errors.New("unsupported algorism")
}

// UnmarshalJSONPrivateKey decode JWK JSON format privatekey.
func UnmarshalJSONPrivateKey(b []byte) (PrivateKey, error) {
	pub := &struct {
		Type  string `json:"kty"`
		Curve string `json:"crv"`
	}{}

	err := json.Unmarshal(b, pub)
	if err != nil {
		return nil, err
	}

	if pub.Type == "RSA" {
		rsakey := &RSAPrivateKey{}
		err := unmarshalJSONRSAPrivateKey(b, rsakey)
		return rsakey, err
	} else if pub.Type == "EC" {
		eckey := &ECPrivateKey{}
		err := unmarshalJSONECPrivateKey(b, eckey)
		return eckey, err
		/*
			if pub.Curve == "P-256" {
				return unmarshalJSONECPrivateKey("ES256", b, eckey)
			} else if pub.Curve == "P-384" {
				return unmarshalJSONECPrivateKey("ES384", b, eckey)
			} else if pub.Curve == "P-521" {
				return unmarshalJSONECPrivateKey("ES512", b, eckey)
			}
		*/
	}

	return nil, errors.New("unsupported algorithm")
}

// UnmarshalJSONPublicKey decode JWK JSON format publickey.
func UnmarshalJSONPublicKey(b []byte) (PublicKey, error) {
	pub := &struct {
		Type  string `json:"kty"`
		Curve string `json:"crv"`
	}{}

	err := json.Unmarshal(b, pub)
	if err != nil {
		return nil, err
	}

	if pub.Type == "RSA" {
		rsakey := &RSAPublicKey{}
		err := unmarshalJSONRSAPublicKey(b, rsakey)
		return rsakey, err
	} else if pub.Type == "EC" {
		eckey := &ECPublicKey{}
		err := unmarshalJSONECPublicKey(b, eckey)
		return eckey, err

		/*
			if pub.Curve == "P-256" {
				return unmarshalJSONECPublicKey("ES256", b)
			} else if pub.Curve == "P-384" {
				return unmarshalJSONECPublicKey("ES384", b)
			} else if pub.Curve == "P-521" {
				return unmarshalJSONECPublicKey("ES512", b)
			}
		*/
	}

	return nil, errors.New("unsupported algorithm")
}

// UnmarshalSSHWirePublicKey decode SSH Wire format publickey.
func UnmarshalSSHWirePublicKey(b []byte) (PublicKey, error) {
	sshpub, err := ssh.ParsePublicKey(b)
	if err != nil {
		return nil, err
	}

	parsedCryptoKey := sshpub.(ssh.CryptoPublicKey)

	// Then, we can call CryptoPublicKey() to get the actual crypto.PublicKey
	pubCrypto := parsedCryptoKey.CryptoPublicKey()

	// Finally, we can convert back to an *rsa.PublicKey
	pub, ok := pubCrypto.(*rsa.PublicKey)
	if ok {
		return (*RSAPublicKey)(pub), nil
	}

	// Finally, we can convert back to an *rsa.PublicKey
	pub2, ok := pubCrypto.(*ecdsa.PublicKey)
	if ok {
		return (*ECPublicKey)(pub2), nil
	}

	return nil, errors.New("convert publickey failed")
}

/*
// UnmarshalSSHWirePrivateKey decode SSH Wire format privatekey.
func UnmarshalSSHWirePrivateKey(b []byte) (PrivateKey, error) {

	sshpk, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, err
	}

	parsedCryptoKey := sshpk.(ssh.CryptoPri)

	// Then, we can call CryptoPublicKey() to get the actual crypto.PublicKey
	pubCrypto := parsedCryptoKey.CryptoPublicKey()

	// Finally, we can convert back to an *rsa.PublicKey
	pub, ok := pubCrypto.(*rsa.PublicKey)
	if ok {
		return (*RSAPublicKey)(pub), nil
	}

	// Finally, we can convert back to an *rsa.PublicKey
	pub2, ok := pubCrypto.(*ecdsa.PublicKey)
	if ok {
		return (*ECPublicKey)(pub2), nil
	}

	return nil, errors.New("convert publickey failed")
}
*/
