// cryptino_ec_invalid_test.go
package cryptino

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

// ---- helpers ----

func b64urlFixed(i *big.Int, size int) string {
	b := i.Bytes()
	if len(b) < size {
		p := make([]byte, size)
		copy(p[size-len(b):], b)
		b = p
	} else if len(b) > size {
		b = b[len(b)-size:]
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func genValidECKeyP256(t *testing.T) *ECPrivateKey {
	t.Helper()
	cs := ES256()
	k, err := cs.GenerateKey(cs)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ec := k.(*ECPrivateKey)
	return ec
}

// ---- tests ----

// 未知の curve 名は error
func TestECPublicKey_Unmarshal_UnknownCurve(t *testing.T) {
	// 適当なX,Y（0x01）だが、まず crv でエラーになる想定
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256K", // 未知
		"x":   "AQ",     // 0x01
		"y":   "AQ",
	}
	buf, _ := json.Marshal(jwk)

	var pub ECPublicKey
	if err := json.Unmarshal(buf, &pub); err == nil {
		t.Fatal("expected error for unknown curve, got nil")
	}
}

// オフカーブ点（Xを1だけズラす）→ error
func TestECPublicKey_Unmarshal_OffCurve(t *testing.T) {
	ec := genValidECKeyP256(t)
	curve := ec.Curve
	size := (curve.Params().BitSize + 7) / 8

	// 既存のYはそのまま、Xだけ +1 してオフカーブに寄せる
	badX := new(big.Int).Add(ec.X, big.NewInt(1))
	// mod P で丸める（それでもほぼ確実に曲線上に乗らない）
	badX.Mod(badX, curve.Params().P)

	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64urlFixed(badX, size),
		"y":   b64urlFixed(ec.Y, size),
	}
	buf, _ := json.Marshal(jwk)

	var pub ECPublicKey
	if err := json.Unmarshal(buf, &pub); err == nil {
		t.Fatal("expected error for off-curve point, got nil")
	}
}

// PrivateKey: D が [1, N-1] 外（=N）→ error
func TestECPrivateKey_Unmarshal_InvalidD(t *testing.T) {
	ec := genValidECKeyP256(t)
	curve := ec.Curve
	size := (curve.Params().BitSize + 7) / 8
	N := curve.Params().N

	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		// 公開点は有効なまま
		"x": b64urlFixed(ec.X, size),
		"y": b64urlFixed(ec.Y, size),
		// D を N（無効）に
		"d": b64urlFixed(N, size),
	}
	buf, _ := json.Marshal(jwk)

	var priv ECPrivateKey
	if err := json.Unmarshal(buf, &priv); err == nil {
		t.Fatal("expected error for invalid private scalar D>=N, got nil")
	}
}

// PrivateKey: 公開点がオフカーブでも reject されること
func TestECPrivateKey_Unmarshal_OffCurvePoint(t *testing.T) {
	ec := genValidECKeyP256(t)
	curve := ec.Curve
	size := (curve.Params().BitSize + 7) / 8

	badX := new(big.Int).Add(ec.X, big.NewInt(1))
	badX.Mod(badX, curve.Params().P)

	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64urlFixed(badX, size),
		"y":   b64urlFixed(ec.Y, size),
		"d":   b64urlFixed(ec.D, size), // D は有効でも公開点が不正なら失敗すべき
	}
	buf, _ := json.Marshal(jwk)

	var priv ECPrivateKey
	if err := json.Unmarshal(buf, &priv); err == nil {
		t.Fatal("expected error for off-curve public point in private JWK, got nil")
	}
}
