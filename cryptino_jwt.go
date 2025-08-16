package cryptino

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// JSONWebToken is RFC 7519 Compliant JSON Web Token implemenation
// Type is "jwt"
type JSONWebToken struct {
	JSONWebSignature

	Body JWTBody `json:"-"`
}

// JSONWebTokenBodyJSON is RFC 7519 Compliant body of JSON Web Token implemenation
type JWTBody struct {
	Issuer         string `json:"iss,omitempty"`
	Subject        string `json:"sub,omitempty"`
	Audience       string `json:"aud,omitempty"`
	ExpirationTime int64  `json:"exp,omitempty"`
	NotBefore      int64  `json:"nbf,omitempty"`
	IssuedAt       int64  `json:"iat,omitempty"`
	JwtID          string `json:"jti,omitempty"`

	Name   string         `json:"name,omitempty"`
	Custom map[string]any `json:"-"`
}

// GetJWTBasic create unsigned JWT object.
func GetJWTBasic(sub string, ttl_exp time.Duration) *JSONWebToken {
	jwt := &JSONWebToken{}
	jwt.Header.Type = "JWT"
	jwt.Body.Subject = sub
	jwt.Body.ExpirationTime = time.Now().Unix() + int64(ttl_exp)
	return jwt
}

// GetJWT create unsigned JWT object.
func GetJWT() *JSONWebToken {
	jwt := &JSONWebToken{}
	jwt.Header.Type = "JWT"
	return jwt
}

func (b *JSONWebToken) Set(key string, v any) {
	if b.Body.Custom == nil {
		b.Body.Custom = make(map[string]any)
	}
	b.Body.Custom[key] = v
}

// 標準クレームを上書きされたくない場合はここでブロックするロジックを入れても良い
var reservedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "nbf": {}, "iat": {}, "jti": {},
	"name": {},
}

func (b JWTBody) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, 8+(len(b.Custom)))
	if b.Issuer != "" {
		m["iss"] = b.Issuer
	}
	if b.Subject != "" {
		m["sub"] = b.Subject
	}
	if b.Audience != "" {
		m["aud"] = b.Audience
	}
	if b.ExpirationTime != 0 {
		m["exp"] = b.ExpirationTime
	}
	if b.NotBefore != 0 {
		m["nbf"] = b.NotBefore
	}
	if b.IssuedAt != 0 {
		m["iat"] = b.IssuedAt
	}
	if b.JwtID != "" {
		m["jti"] = b.JwtID
	}
	if b.Name != "" {
		m["name"] = b.Name
	}

	for k, v := range b.Custom {
		// 標準名と衝突する場合のポリシー（上書き/無視/エラー）を選ぶ
		if _, reserved := reservedClaims[k]; reserved {
			// 例: 上書き禁止にするなら continue かエラーにする
			continue
		}
		m[k] = v
	}
	return json.Marshal(m)
}

// Marshal encode JWT and add its signature.
func (jwt *JSONWebToken) Marshal(cs *CipherSuite, signer Signer) (string, error) {
	b, err := json.Marshal(jwt.Body)
	if err != nil {
		return "", err
	}

	jwt.RawBody = b
	return jwt.JSONWebSignature.Marshal(cs, signer)
}

// PrintInJSON print JWT to stdout
func (jwt *JSONWebToken) PrintInJSON(prefix string, indent string) {
	oj, _ := json.MarshalIndent(jwt.Header, prefix, indent)
	fmt.Printf("%s\n", oj)
	fmt.Printf("%s", prefix)
	oj, _ = json.MarshalIndent(jwt.Body, prefix, indent)
	fmt.Printf("%s\n", oj)
}

// VerifyJWT verifies signature and its header.
// UNDERCONSTRUCTION.
func VerifyJWT(cs *CipherSuite, token []byte, veri Verifier) (*JSONWebToken, error) {
	sig, err := UnmarshalJSONJOSE(cs, token, veri)
	if err != nil {
		return nil, err
	}

	// check JOSE Header
	//v := sig.Verify(cs, veri)
	//if !v {
	//	return nil, errors.New("signature error")
	//}

	jwt := &JSONWebToken{
		JSONWebSignature: *sig,
	}

	err = json.Unmarshal(sig.RawBody, &jwt.Body)
	if err != nil {
		return nil, err
	}

	// check JWT body
	now := time.Now().Unix()

	//fmt.Println("VerifyJWT:", now, ", ", jwt.Body.ExpirationTime)
	if jwt.Body.ExpirationTime != 0 && jwt.Body.ExpirationTime < now {
		return nil, errors.New("exp expired")
	}

	if jwt.Body.NotBefore != 0 && jwt.Body.NotBefore > now {
		return nil, errors.New("nbf expired")
	}

	return jwt, nil
}
