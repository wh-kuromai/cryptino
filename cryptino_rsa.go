package cryptino

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"golang.org/x/crypto/ssh"
)

type RSAPrivateKey rsa.PrivateKey

type RSAPublicKey rsa.PublicKey

type rsaPrivateKeyJSON struct {
	*rsaPublicKeyJSON
	D  string `json:"d"`
	P  string `json:"p"`
	Q  string `json:"q"`
	Dp string `json:"-"` //dp
	Dq string `json:"-"` //dq
	Qi string `json:"-"` //qi
}

// ECPublicKeyJSON is RFC Compliant JSON Web Key implemenation
// Type is "jwk"
type rsaPublicKeyJSON struct {
	Type string `json:"kty"`
	//Algorithm string   `json:"alg,omitempty"`
	KeyID  string   `json:"kid,omitempty"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	Use    string   `json:"use,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
}

// Bits returns encryption bit length
func Bits(alg string) int {
	if strings.Contains(alg, "SHA256") {
		return 2048
	} else if strings.Contains(alg, "SHA386") {
		return 3072
	} else if strings.Contains(alg, "SHA512") {
		return 4096
	}

	return 2048
}

func GenerateRSAKey(cs *CipherSuite) (*RSAPrivateKey, error) {
	pk, err := rsa.GenerateKey(rand.Reader, cs.Bit)
	if err != nil {
		return nil, err
	}

	return (*RSAPrivateKey)(pk), nil
}

func convertRSAPrivateKeyJSON(pk *rsa.PrivateKey) *rsaPrivateKeyJSON {
	pub := &pk.PublicKey
	privjson := &rsaPrivateKeyJSON{
		rsaPublicKeyJSON: &rsaPublicKeyJSON{
			Type: "RSA",
			//Algorithm: alg,
			N: encodeBigInt(pub.N),
			E: encodeInt(pub.E),
		},
		D:  encodeBigInt(pk.D),
		P:  encodeBigInt(pk.Primes[0]),
		Q:  encodeBigInt(pk.Primes[1]),
		Dp: encodeBigInt(pk.Precomputed.Dp),
		Dq: encodeBigInt(pk.Precomputed.Dq),
		Qi: encodeBigInt(pk.Precomputed.Qinv),
	}
	return privjson
}

func convertRSAPublicKeyJSON(pub *rsa.PublicKey) *rsaPublicKeyJSON {
	pubjson := &rsaPublicKeyJSON{
		Type: "RSA",
		//Algorithm: alg,
		N: encodeBigInt(pub.N),
		E: encodeInt(pub.E),
	}
	return pubjson
}

func unmarshalJSONRSAPrivateKey(jsn []byte, key *RSAPrivateKey) error {
	pkj := &rsaPrivateKeyJSON{}
	err := json.Unmarshal(jsn, pkj)
	if err != nil {
		return err
	}

	key.N = decodeBigInt(pkj.N)
	key.E = decodeInt(pkj.E)
	key.D = decodeBigInt(pkj.D)
	key.Primes = []*big.Int{
		decodeBigInt(pkj.P),
		decodeBigInt(pkj.Q),
	}

	err = (*rsa.PrivateKey)(key).Validate()
	if err != nil {
		return err
	}

	(*rsa.PrivateKey)(key).Precompute()
	return nil
}

func unmarshalJSONRSAPublicKey(jsn []byte, key *RSAPublicKey) error {
	pkj := &rsaPublicKeyJSON{}
	err := json.Unmarshal(jsn, pkj)
	if err != nil {
		return err
	}

	key.N = decodeBigInt(pkj.N)
	key.E = decodeInt(pkj.E)
	return nil
}

// MarshalJSON encode RSAPrivateKey into JSON.
func (key *RSAPrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(convertRSAPrivateKeyJSON((*rsa.PrivateKey)(key)))
}

func (key *RSAPrivateKey) UnmarshalJSON(buf []byte) error {
	return unmarshalJSONRSAPrivateKey(buf, key)
}

// MarshalJSON encode RSAPublicKey into JSON.
func (key *RSAPublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(convertRSAPublicKeyJSON((*rsa.PublicKey)(key)))
}

func (key *RSAPublicKey) UnmarshalJSON(buf []byte) error {
	return unmarshalJSONRSAPublicKey(buf, key)
}

func (key *RSAPublicKey) MarshalSSHWire() []byte {
	sshpub, err := ssh.NewPublicKey((*rsa.PublicKey)(key))
	if err != nil {
		return nil
	}
	return sshpub.Marshal()
}

// PublicKey returns PublicKey inside this RSAPrivateKey.
func (key *RSAPrivateKey) Public() PublicKey {
	return (*RSAPublicKey)(&key.PublicKey)
}

// Name
func (key *RSAPrivateKey) Name() string {
	return "RSA"
}

// Name
func (key *RSAPublicKey) Name() string {
	return "RSA"
}

// Size
func (key *RSAPublicKey) Size() int {
	return (*rsa.PublicKey)(key).Size()
}

func (key *RSAPrivateKey) Encrypt(cs *CipherSuite, remote PublicKey, msg []byte) ([]byte, error) {
	pubkey, ok := remote.(*RSAPublicKey)
	if !ok {
		return nil, errors.New("key not match")
	}

	shared := make([]byte, key.Size()/8)
	rand.Read(shared)

	encShared, err := rsa.EncryptOAEP(hashFromSize(key.Size()).New(), rand.Reader, (*rsa.PublicKey)(pubkey), shared, nil)
	if err != nil {
		return nil, err
	}

	//fmt.Println("SIZEOFSHARED", len(encShared))

	enc, err := EncryptByGCM(shared, msg)
	if err != nil {
		return nil, err
	}

	encShared = append(encShared, enc...)

	//fmt.Println("signbody", base64.RawStdEncoding.EncodeToString(encShared))
	sign, err := key.Signature(cs, encShared)
	if err != nil {
		return nil, err
	}
	//fmt.Println("SIZEOFSign", len(sign))

	encShared = append(encShared, sign...)

	//fmt.Println("sign", base64.RawStdEncoding.EncodeToString(sign))

	return encShared, nil
}

func (key *RSAPrivateKey) Decrypt(cs *CipherSuite, remote PublicKey, msg []byte) ([]byte, error) {
	pubkey, ok := remote.(*RSAPublicKey)
	if !ok {
		return nil, errors.New("key not match")
	}

	encShared := msg[0:key.Size()]
	enc := msg[key.Size() : len(msg)-key.Size()]
	signbody := msg[:len(msg)-key.Size()]
	sign := msg[len(msg)-key.Size():]

	shared, err := rsa.DecryptOAEP(hashFromSize(key.Size()).New(), rand.Reader, (*rsa.PrivateKey)(key), encShared, nil)
	if err != nil {
		return nil, err
	}

	//fmt.Println("signbody", base64.RawStdEncoding.EncodeToString(signbody))
	//fmt.Println("sign2", base64.RawStdEncoding.EncodeToString(sign))
	if !pubkey.Verify(cs, signbody, sign) {
		return nil, errors.New("signature error")
	}

	return DecryptByGCM(shared, enc)
}

// Signature calculate signature.
func (key *RSAPrivateKey) Signature(cs *CipherSuite, msg []byte) ([]byte, error) {
	if strings.Contains(cs.Padding, "PKCS1") {
		return rsa.SignPKCS1v15(rand.Reader, (*rsa.PrivateKey)(key), hashFromSize(key.Size()), hashAlgFromSize(key.Size())(msg))
	}

	return rsa.SignPSS(rand.Reader, (*rsa.PrivateKey)(key), hashFromSize(key.Size()), hashAlgFromSize(key.Size())(msg), nil)
}

// Verify verifies signature.
func (key *RSAPublicKey) Verify(cs *CipherSuite, msg []byte, sign []byte) bool {
	if strings.Contains(cs.Padding, "PKCS1") {
		return rsa.VerifyPKCS1v15((*rsa.PublicKey)(key), hashFromSize(key.Size()), hashAlgFromSize(key.Size())(msg), sign) == nil
	}

	return rsa.VerifyPSS((*rsa.PublicKey)(key), hashFromSize(key.Size()), hashAlgFromSize(key.Size())(msg), sign, nil) == nil
}

// Thumbprint creates RFC 7638 compliant Public Key identifier.
func (key *RSAPublicKey) Thumbprint(cs *CipherSuite) string {

	pubjson := convertRSAPublicKeyJSON((*rsa.PublicKey)(key))

	thumbobj := struct {
		E    string `json:"e"`
		Type string `json:"kty"`
		N    string `json:"n"`
	}{
		E:    pubjson.E,
		Type: pubjson.Type,
		N:    pubjson.N,
	}

	thumbbase, _ := json.Marshal(thumbobj)
	thumb := cs.Hash(thumbbase)
	return base64.RawURLEncoding.EncodeToString(thumb)
}
