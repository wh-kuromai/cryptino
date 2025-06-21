package cryptino

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// JOSEHeader is RFC 7515 Compliant JOSE Header implementation of JSON Web Signature
type JOSEHeader struct {
	Type        string          `json:"typ,omitempty"`
	Algorithm   string          `json:"alg"`
	JwkURL      string          `json:"jku,omitempty"`
	Jwk         json.RawMessage `json:"jwk,omitempty"`
	KeyID       string          `json:"kid,omitempty"`
	ContentType string          `json:"cty,omitempty"`
	Critical    []string        `json:"crit,omitempty"` // TODO: not implemented yet
}

// JSONWebSignature is RFC 7515 Compliant JSON Web Signature implemenation
// Type is "jose"
type JSONWebSignature struct {
	Header  JOSEHeader      `json:"head"`
	RawBody json.RawMessage `json:"body"`
	Sign    string          `json:"sign"`
	raw     string
}

/*
func getJWS(head *JOSEHeader, body []byte) *JSONWebSignature {
	return &JSONWebSignature{
		Header:  head,
		RawBody: body,
	}
}
*/

func getJWTAlg(alg string) string {
	if strings.Contains(alg, "RSA") {
		if strings.Contains(alg, "SHA256") {
			return "RS256"
		} else if strings.Contains(alg, "SHA386") {
			return "RS386"
		} else if strings.Contains(alg, "SHA512") {
			return "RS512"
		}
	} else if strings.Contains(alg, "ECDSA") {
		if strings.Contains(alg, "SHA256") {
			return "ES256"
		} else if strings.Contains(alg, "SHA386") {
			return "ES386"
		} else if strings.Contains(alg, "SHA512") {
			return "ES512"
		}
	}

	return ""
}

// Verify signature
func (sig *JSONWebSignature) Verify(cs *CipherSuite, veri Verifier) bool {

	jwsspl := strings.Split(sig.raw, ".")
	if len(jwsspl) != 3 {
		return false
	}

	signbytes, err := base64.RawURLEncoding.DecodeString(jwsspl[2])
	if err != nil {
		return false
	}

	if sig.Header.Critical != nil {
		return false
	}

	return veri.Verify(cs, []byte(jwsspl[0]+"."+jwsspl[1]), signbytes)
}

// Marshal into RFC 7515 compliant JSON Web Signature
func (sig *JSONWebSignature) Marshal(cs *CipherSuite, signer Signer) (string, error) {
	sig.Header.Algorithm = getJWTAlg(signer.Name() + "-SHA" + strconv.Itoa(signer.Size()))

	headjsn, err := json.Marshal(sig.Header)
	if err != nil {
		return "", err
	}

	headb64 := base64.RawURLEncoding.EncodeToString(headjsn)
	bodyb64 := base64.RawURLEncoding.EncodeToString(sig.RawBody)

	tgt := headb64 + "." + bodyb64
	sign, err := signer.Signature(cs, []byte(tgt))
	if err != nil {
		return "", err
	}

	res := tgt + "." + base64.RawURLEncoding.EncodeToString(sign)

	return res, nil
}

// UnmarshalJSONJOSE decode RFC 7515 compliant JSON Web Signature
func UnmarshalJSONJOSE(cs *CipherSuite, b []byte, veri Verifier) (*JSONWebSignature, error) {
	jws := string(b)
	jwsspl := strings.Split(jws, ".")
	if len(jwsspl) != 3 {
		return nil, errors.New("JWS format error (couldn't split into 3 base64 strings)")
	}

	headbytes, err := base64.RawURLEncoding.DecodeString(jwsspl[0])
	if err != nil {
		return nil, err
	}

	jose := &JSONWebSignature{}
	err = json.Unmarshal(headbytes, &jose.Header)
	if err != nil {
		return nil, err
	}

	bodybytes, err := base64.RawURLEncoding.DecodeString(jwsspl[1])
	if err != nil {
		return nil, err
	}

	jose.RawBody = bodybytes
	jose.raw = jws
	jose.Sign = string(jwsspl[2])

	if jose.Verify(cs, veri) {
		return jose, nil
	}

	return nil, errors.New("JWS verify error")
}
