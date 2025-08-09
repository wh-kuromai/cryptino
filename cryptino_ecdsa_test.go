// cryptino_ec_test.go
package cryptino

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

func TestECDSA_ES256_SignVerify(t *testing.T) {
	cs := ES256()

	// 鍵生成
	privAny, err := cs.GenerateKey(cs)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, ok := privAny.(*ECPrivateKey)
	if !ok {
		t.Fatal("not ECPrivateKey")
	}
	pubAny := ecPriv.Public()
	ecPub, ok := pubAny.(*ECPublicKey)
	if !ok {
		t.Fatal("not ECPublicKey")
	}

	msg := []byte("hello ecdsa")

	// 署名→検証
	sig, err := ecPriv.Signature(cs, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ecPub.Verify(cs, msg, sig) {
		t.Fatal("verify failed")
	}

	// 改ざん（1byte）
	sig[0] ^= 0x01
	if ecPub.Verify(cs, msg, sig) {
		t.Fatal("tampered signature should fail")
	}
}

func TestECDSA_ES256_RawSignatureLengthFixed(t *testing.T) {
	cs := ES256()
	privAny, _ := cs.GenerateKey(cs)
	ecPriv := privAny.(*ECPrivateKey)
	bit := (*ECPublicKey)(&ecPriv.PublicKey).sigBits() // P-256 => 32

	for i := 0; i < 16; i++ {
		sig, err := ecPriv.Signature(cs, []byte{byte(i)})
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if len(sig) != bit*2 {
			t.Fatalf("raw sig length want %d got %d", bit*2, len(sig))
		}
	}
}

func TestECDSA_ES256_LowS(t *testing.T) {
	cs := ES256()
	privAny, _ := cs.GenerateKey(cs)
	ecPriv := privAny.(*ECPrivateKey)
	ecPub := (*ECPublicKey)(&ecPriv.PublicKey)

	sig, err := ecPriv.Signature(cs, []byte("low-s-check"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tbi, err := ecPub.splitRS(sig)
	if err != nil {
		t.Fatalf("splitRS: %v", err)
	}

	N := ecPub.Curve.Params().N
	half := new(big.Int).Rsh(new(big.Int).Set(N), 1)
	if tbi.b.Cmp(half) == 1 {
		t.Fatalf("s must be low-S (<= N/2), got s > N/2")
	}
}

func TestECDH_GCM_RoundTrip(t *testing.T) {
	cs := ES256()

	// 送信者/受信者鍵
	senderAny, _ := cs.GenerateKey(cs)
	receiverAny, _ := cs.GenerateKey(cs)
	sender := senderAny.(*ECPrivateKey)
	receiver := receiverAny.(*ECPrivateKey)

	msg := []byte("ecdh hkdf aes-gcm 🎯")

	// 送信者が受信者の公開鍵で暗号化
	ct, err := sender.Encrypt(cs, receiver.Public(), msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// 受信者が送信者の公開鍵で復号
	pt, err := receiver.Decrypt(cs, sender.Public(), ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("mismatch: got %q want %q", pt, msg)
	}

	// 改ざん → GCM認証エラー期待
	ct[len(ct)-1] ^= 0x01
	if _, err := receiver.Decrypt(cs, sender.Public(), ct); err == nil {
		t.Fatal("tamper must fail")
	}
}

func TestEC_JWK_MarshalUnmarshal_And_Thumbprint(t *testing.T) {
	cs := ES256()
	privAny, _ := cs.GenerateKey(cs)
	ecPriv := privAny.(*ECPrivateKey)
	ecPub := (*ECPublicKey)(&ecPriv.PublicKey)

	// Thumbprint 安定性テスト（Marshal/Unmarshal 後も同じ）
	tp1 := ecPub.Thumbprint(cs)
	if tp1 == "" {
		t.Fatal("empty thumbprint")
	}

	// Public JWK
	pubJSON, err := json.Marshal(ecPub)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var pub2 ECPublicKey
	if err := json.Unmarshal(pubJSON, &pub2); err != nil {
		t.Fatalf("pub unmarshal: %v", err)
	}
	tp2 := (*ECPublicKey)(&pub2).Thumbprint(cs)
	if tp1 != tp2 {
		t.Fatalf("thumbprint not stable: %s vs %s", tp1, tp2)
	}

	// Private JWK（d 含む）→ 復元して署名/検証
	privJSON, err := json.Marshal(ecPriv)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var priv2 ECPrivateKey
	if err := json.Unmarshal(privJSON, &priv2); err != nil {
		t.Fatalf("priv unmarshal: %v", err)
	}

	msg := []byte("jwk roundtrip")
	sig, err := priv2.Signature(cs, msg)
	if err != nil {
		t.Fatalf("Signature: %v", err)
	}
	if !(*ECPublicKey)(&priv2.PublicKey).Verify(cs, msg, sig) {
		t.Fatal("verify failed after JWK roundtrip")
	}

	// 署名長の sanity
	raw, _ := base64.RawURLEncoding.DecodeString(base64.RawURLEncoding.EncodeToString(sig))
	if len(raw) != 64 {
		t.Fatalf("raw signature length want 64 got %d", len(raw))
	}
}
