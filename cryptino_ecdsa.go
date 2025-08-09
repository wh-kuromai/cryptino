package cryptino

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

type ECPrivateKey ecdsa.PrivateKey
type ECPublicKey ecdsa.PublicKey

type ECPrivateKeyJSON struct {
	*ECPublicKeyJSON
	D string `json:"d"`
}

// ECPublicKeyJSON is RFC Compliant JSON Web Key implemenation
// Type is "jwk"
type ECPublicKeyJSON struct {
	Type string `json:"kty"`
	//Algorithm string   `json:"alg,omitempty"`
	Curve  string   `json:"crv"`
	KeyID  string   `json:"kid,omitempty"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
	Use    string   `json:"use,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
}

/*
// Curve returns elliptic curve used by specified algorism.
func Curve(alg string) elliptic.Curve {
	switch alg {
	case "ES256":
		return elliptic.P256()
	case "ES384":
		return elliptic.P384()
	case "ES512":
		return elliptic.P521()
	}

	panic("unsupported algorithm")
}
*/

// Curve returns elliptic curve used by specified algorism.
func ccurve(alg string) elliptic.Curve {
	switch alg {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	}

	panic("unsupported algorithm")
}

func (key *ECPublicKey) sigBits() int {
	switch key.Curve {
	case elliptic.P256():
		return 32
	case elliptic.P384():
		return 48
	case elliptic.P521():
		return 66
	}

	panic("unsupported curve")
}

func decodeBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	r := &big.Int{}
	r.SetBytes(b)
	return r, nil
}

func encodeBigInt(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}

func decodeInt(s string) (int, error) {
	bi, err := decodeBigInt(s)
	if err != nil {
		return 0, err
	}
	return int(bi.Int64()), nil
}

func encodeInt(i int) string {
	r := &big.Int{}
	r.SetInt64(int64(i))
	return encodeBigInt(r)
}

func GenerateECKey(cs *CipherSuite) (*ECPrivateKey, error) {
	pk, err := ecdsa.GenerateKey(cs.Curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return (*ECPrivateKey)(pk), nil
}

func convertECPrivateKeyJSON(pk *ecdsa.PrivateKey) *ECPrivateKeyJSON {
	pub := &pk.PublicKey
	privjson := &ECPrivateKeyJSON{
		ECPublicKeyJSON: &ECPublicKeyJSON{
			Type: "EC",
			//Algorithm: alg,
			Curve: pub.Params().Name,
			X:     encodeBigInt(pub.X),
			Y:     encodeBigInt(pub.Y),
		},
		D: encodeBigInt(pk.D),
	}

	//p.ECPublicKey.pubjson.KeyID = p.ECPublicKey.Thumbprint()
	return privjson
}

func convertECPublicKeyJSON(pub *ecdsa.PublicKey) *ECPublicKeyJSON {
	pubjson := &ECPublicKeyJSON{
		Type: "EC",
		//Algorithm: alg,
		Curve: pub.Params().Name,
		X:     encodeBigInt(pub.X),
		Y:     encodeBigInt(pub.Y),
	}

	return pubjson
}

func unmarshalJSONECPrivateKey(jsn []byte, key *ECPrivateKey) error {
	pkj := &ECPrivateKeyJSON{}
	err := json.Unmarshal(jsn, pkj)
	if err != nil {
		return err
	}

	key.Curve = ccurve(pkj.Curve)
	key.X, err = decodeBigInt(pkj.X)
	if err != nil {
		return err
	}
	key.Y, err = decodeBigInt(pkj.Y)
	if err != nil {
		return err
	}
	key.D, err = decodeBigInt(pkj.D)
	if err != nil {
		return err
	}
	return nil
}

func unmarshalJSONECPublicKey(jsn []byte, key *ECPublicKey) error {
	pkj := &ECPublicKeyJSON{}
	err := json.Unmarshal(jsn, pkj)
	if err != nil {
		return err
	}

	key.Curve = ccurve(pkj.Curve)
	key.X, err = decodeBigInt(pkj.X)
	if err != nil {
		return err
	}
	key.Y, err = decodeBigInt(pkj.Y)
	if err != nil {
		return err
	}
	return nil
}

// MarshalJSON encode RSAPrivateKey into JSON.
func (key *ECPrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(convertECPrivateKeyJSON((*ecdsa.PrivateKey)(key)))
}

func (key *ECPrivateKey) UnmarshalJSON(buf []byte) error {
	return unmarshalJSONECPrivateKey(buf, key)
}

// MarshalJSON encode ECPublicKey into JSON.
func (key *ECPublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(convertECPublicKeyJSON((*ecdsa.PublicKey)(key)))
}

func (key *ECPublicKey) UnmarshalJSON(buf []byte) error {
	return unmarshalJSONECPublicKey(buf, key)
}

func (key *ECPublicKey) MarshalSSHWire() []byte {
	sshpub, err := ssh.NewPublicKey((*ecdsa.PublicKey)(key))
	if err != nil {
		return nil
	}
	return sshpub.Marshal()
}

// Name
func (key *ECPrivateKey) Name() string {
	return "ECDSA"
}

// Name
func (key *ECPublicKey) Name() string {
	return "ECDSA"
}

// Size
func (key *ECPublicKey) Size() int {
	switch key.Curve {
	case elliptic.P256():
		return 256
	case elliptic.P384():
		return 384
	case elliptic.P521():
		return 512
	}
	return 256
}

//func (key *ECPublicKey) hashAlg() Hash {
//	switch key.Curve {
//	case elliptic.P256():
//		return SHA256
//	case elliptic.P384():
//		return SHA384
//	case elliptic.P521():
//		return SHA512
//	}
//	return SHA256
//}

// Size
func (key *ECPrivateKey) Size() int {
	return (*ECPublicKey)(&key.PublicKey).Size()
}

// PublicKey returns PublicKey inside this RSAPrivateKey.
func (key *ECPrivateKey) Public() PublicKey {
	return (*ECPublicKey)(&key.PublicKey)
}

func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b[len(b)-n:]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func joinRS(bit int, r, s *big.Int) []byte {
	rb := leftPad(r.Bytes(), bit)
	sb := leftPad(s.Bytes(), bit)
	out := make([]byte, 0, bit*2)
	out = append(out, rb...)
	out = append(out, sb...)
	return out
}

type twoBigInt struct {
	a *big.Int
	b *big.Int
}

func (key *ECPublicKey) splitRS(sign []byte) (*twoBigInt, error) {
	bit := key.sigBits()
	if len(sign) != bit*2 {
		return nil, errors.New("rs sign length error")
	} // ここは好みで false 戻しに
	var R, S big.Int
	R.SetBytes(sign[0:bit])
	S.SetBytes(sign[bit:])
	return &twoBigInt{&R, &S}, nil
}

func (key *ECPrivateKey) ECDHShared(remote *ecdsa.PublicKey) ([]byte, error) {
	ecdhkey, err := (*ecdsa.PrivateKey)(key).ECDH()
	if err != nil {
		return nil, err
	}

	ecdhpub, err := remote.ECDH()
	if err != nil {
		return nil, err
	}

	return ecdhkey.ECDH(ecdhpub)
}

func deriveAESKey(shared []byte, keyLen int, info []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, shared, nil, info)
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func (key *ECPrivateKey) Encrypt(cs *CipherSuite, remote PublicKey, msg []byte) ([]byte, error) {
	pubkey, ok := remote.(*ECPublicKey)
	if !ok {
		return nil, errors.New("key not match")
	}

	shared, err := key.ECDHShared((*ecdsa.PublicKey)(pubkey))
	if err != nil {
		return nil, err
	}

	aesKey, err := deriveAESKey(shared, 32, []byte("ECDH-ES AES-256-GCM"))
	if err != nil {
		return nil, err
	}
	return EncryptByGCM(aesKey, msg)
}

func (key *ECPrivateKey) Decrypt(cs *CipherSuite, remote PublicKey, msg []byte) ([]byte, error) {
	pubkey, ok := remote.(*ECPublicKey)
	if !ok {
		return nil, errors.New("key not match")
	}

	shared, err := key.ECDHShared((*ecdsa.PublicKey)(pubkey))
	if err != nil {
		return nil, err
	}

	aesKey, err := deriveAESKey(shared, 32, []byte("ECDH-ES AES-256-GCM"))
	if err != nil {
		return nil, err
	}
	return DecryptByGCM(aesKey, msg)
}

func normalizeS(curve elliptic.Curve, s *big.Int) *big.Int {
	n := curve.Params().N
	half := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if s.Cmp(half) == 1 {
		s = new(big.Int).Sub(n, s)
	}
	return s
}

func (key *ECPrivateKey) Signature(cs *CipherSuite, msg []byte) ([]byte, error) {
	h := cs.HashEncode(msg)
	//h := hashAlgFromSize(key.Size())(msg)
	r, s, err := ecdsa.Sign(rand.Reader, (*ecdsa.PrivateKey)(key), h)
	if err != nil {
		return nil, err
	}
	s = normalizeS(key.Curve, s)
	return joinRS((*ECPublicKey)(&key.PublicKey).sigBits(), r, s), nil
}

// Verify verifies signature.
func (key *ECPublicKey) Verify(cs *CipherSuite, msg []byte, sign []byte) bool {
	tbi, err := key.splitRS(sign)
	if err != nil {
		return false
	}
	return ecdsa.Verify((*ecdsa.PublicKey)(key), cs.HashEncode(msg), tbi.a, tbi.b)
}

// Thumbprint creates RFC 7638 compliant Public Key identifier.
func (key *ECPublicKey) Thumbprint(cs *CipherSuite) string {
	pubjson := convertECPublicKeyJSON((*ecdsa.PublicKey)(key))
	thumbobj := struct {
		Curve string `json:"crv"`
		Type  string `json:"kty"`
		X     string `json:"x"`
		Y     string `json:"y"`
	}{
		Curve: pubjson.Curve,
		Type:  pubjson.Type,
		X:     pubjson.X,
		Y:     pubjson.Y,
	}

	thumbbase, _ := json.Marshal(thumbobj)
	thumb := cs.HashEncode(thumbbase)
	//key.thumb =
	return base64.RawURLEncoding.EncodeToString(thumb)
}
