package cryptino

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// ヘルパ
func must[T any](t *testing.T, v T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return v
}

// --- JWS / JWT ---

func TestJWS_RS256_SignVerify(t *testing.T) {
	cs := RS256()
	priv, err := cs.GenerateKey(cs)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()

	// JWSヘッダ＋ボディ
	sig := &JSONWebSignature{
		Header:  JOSEHeader{Type: "JWT"}, // typは任意
		RawBody: json.RawMessage(`{"sub":"alice","iat":1}`),
	}
	jws, err := sig.Marshal(cs, priv)
	if err != nil {
		t.Fatal(err)
	}

	// 受信→検証
	got, err := UnmarshalJSONJOSE(cs, []byte(jws), pub)
	if err != nil {
		t.Fatal(err)
	}

	// 改竄検知（ボディ1バイト変更）
	parts := bytes.Split([]byte(jws), []byte{'.'})
	body, _ := base64.RawURLEncoding.DecodeString(string(parts[1]))
	body[0] ^= 0x01
	parts[1] = []byte(base64.RawURLEncoding.EncodeToString(body))
	tampered := bytes.Join(parts, []byte{'.'})
	if _, err := UnmarshalJSONJOSE(cs, tampered, pub); err == nil {
		t.Fatal("tamper should fail")
	}

	// alg不一致（期待Suite変更）
	if _, err := UnmarshalJSONJOSE(ES256(), []byte(jws), pub); err == nil {
		t.Fatal("alg mismatch should fail")
	}

	if got.Header.Algorithm != cs.Name {
		t.Fatalf("alg mismatch: %s", got.Header.Algorithm)
	}
}

func TestJWS_ES256_SignVerify(t *testing.T) {
	cs := ES256()
	priv, err := cs.GenerateKey(cs)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()

	sig := &JSONWebSignature{
		Header:  JOSEHeader{},
		RawBody: json.RawMessage(`{"hello":"world"}`),
	}
	jws, err := sig.Marshal(cs, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalJSONJOSE(cs, []byte(jws), pub); err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	// 署名長（r||s）境界：固定長であること（長さチェックのみ）
	parts := bytes.Split([]byte(jws), []byte{'.'})
	sigb, err := base64.RawURLEncoding.DecodeString(string(parts[2]))
	if err != nil {
		t.Fatal(err)
	}
	// P-256は64バイト固定
	if len(sigb) != 64 {
		t.Fatalf("ecdsa raw signature length want 64 got %d", len(sigb))
	}
}

func TestJWT_ExpNbf(t *testing.T) {
	cs := ES256()
	priv, err := cs.GenerateKey(cs)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()

	now := time.Now().Unix()
	jwt := &JSONWebToken{}
	jwt.Header.Type = "JWT"
	jwt.Body = JWTBody{
		Subject:        "bob",
		IssuedAt:       now,
		ExpirationTime: now + 2,  // 2秒後
		NotBefore:      now - 10, // 既に有効
	}
	jws, err := jwt.Marshal(cs, priv)
	if err != nil {
		t.Fatal(err)
	}

	// すぐ有効
	if _, err := VerifyJWT(cs, []byte(jws), pub); err != nil {
		t.Fatalf("valid jwt rejected: %v", err)
	}

	// nbf将来（無効）
	jwt2 := &JSONWebToken{}
	jwt2.Header.Type = "JWT"
	jwt2.Body = JWTBody{Subject: "carol", NotBefore: now + 60}
	jws2, err := jwt2.Marshal(cs, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyJWT(cs, []byte(jws2), pub); err == nil {
		t.Fatal("nbf not yet valid should fail")
	}

	// exp経過待ち（2秒）
	time.Sleep(3100 * time.Millisecond)
	if _, err := VerifyJWT(cs, []byte(jws), pub); err == nil {
		t.Fatal("expired jwt should fail")
	}
}

// --- RSA ハイブリッド暗号（OAEP+GCM） ---

func TestRSA_EncryptDecrypt_RoundTrip(t *testing.T) {
	cs := RS256() // Padding: PKCS1v15署名, OAEPはcs.Hash(New)でSHA256
	senderPriv, err := cs.GenerateKey(cs)
	if err != nil {
		t.Fatal(err)
	}
	receiverPriv, err := cs.GenerateKey(cs)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello hybrid crypto")

	ct, err := senderPriv.Encrypt(cs, receiverPriv.Public(), msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	pt, err := receiverPriv.Decrypt(cs, senderPriv.Public(), ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(pt, msg) {
		t.Fatalf("roundtrip mismatch: got %q want %q", pt, msg)
	}

	// 改竄（末尾1バイト変更）→ 署名検証で落ちるはず
	ct[len(ct)-1] ^= 0x01
	if _, err := receiverPriv.Decrypt(cs, senderPriv.Public(), ct); err == nil {
		t.Fatal("tamper ciphertext should fail")
	}
}

func TestThumbprints(t *testing.T) {
	es := ES256()
	ecPriv, err := es.GenerateKey(es)
	if err != nil {
		t.Fatal(err)
	}
	ecThumb := ecPriv.Public().Thumbprint(es)
	if ecThumb == "" {
		t.Fatal("empty ec thumbprint")
	}

	rs := RS256()
	rsPriv, err := rs.GenerateKey(rs)
	if err != nil {
		t.Fatal(err)
	}
	rsThumb := rsPriv.Public().Thumbprint(rs)
	if rsThumb == "" {
		t.Fatal("empty rsa thumbprint")
	}
}
