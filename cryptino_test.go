package cryptino

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestSign(t *testing.T) {

	fmt.Printf("Generate RSA PrivateKey in JWK format.\n")
	rs256pk, _ := GenerateKey("RS256")
	printInJSON(rs256pk)

	fmt.Printf("Output RSA PublicKey in JWK format.\n")
	rs256pub := rs256pk.Public()
	rs256pub.MarshalJSON()
	printInJSON(rs256pub)

	fmt.Printf("Generate EC PrivateKey in JWK format.\n")
	es256pk, _ := GenerateKey("ES256")
	printInJSON(es256pk)

	fmt.Printf("Output EC PublicKey in JWK format.\n")
	es256pub := es256pk.Public()
	es256pubJSON, _ := es256pub.MarshalJSON()
	printInJSON(es256pub)

	fmt.Printf("Parse EC PublicKey JSON into PublicKey object.\n")
	pk, _ := UnmarshalJSONPublicKey(es256pubJSON)
	printInJSON(pk)

	fmt.Printf("Generate JWT using EC PrivateKey.\n")
	jwt := GetJWTBasic("sample", 3000)
	jwtm, _ := jwt.Marshal(ES256(), es256pk)
	jwt.PrintInJSON("", "    ")
	fmt.Printf("%s\n\n", jwtm)

	fmt.Printf("Verify JWT using EC PublicKey.\n")
	jwt2, _ := VerifyJWT(ES256(), []byte(jwtm), es256pub)
	fmt.Printf("Verify: %t\n", jwt2 != nil)
	jwt2.PrintInJSON("", "    ")
	fmt.Printf("\n")

	fmt.Printf("Verify incorrect JWT.\n")
	jwt2, _ = VerifyJWT(ES256(), []byte(string(jwtm)+"ABC"), es256pub)
	fmt.Printf("Verify: %t\n\n", jwt2 != nil)

	fmt.Printf("Generate Second EC PrivateKey.\n")
	es256pk2, _ := GenerateKey("ES256")
	printInJSON(es256pk2)

}

func TestEncode(t *testing.T) {

	fmt.Printf("Generate ECC PrivateKey 1 in JWK format.\n")
	rs256pk1, _ := GenerateKey("ES256")
	printInJSON(rs256pk1)

	rs256pk1ssh := rs256pk1.Public().MarshalSSHWire()

	fmt.Println(base64.RawStdEncoding.EncodeToString(rs256pk1ssh))
}

func TestEncryptRSAGCM(t *testing.T) {

	fmt.Printf("Generate RSA PrivateKey 1 in JWK format.\n")
	rs256pk1, _ := GenerateKey("RS256")
	printInJSON(rs256pk1)

	fmt.Printf("Generate RSA PrivateKey 2 in JWK format.\n")
	rs256pk2, _ := GenerateKey("RS256")
	printInJSON(rs256pk2)

	target := []byte("Encrypt with RSA-GCM")
	buf, _ := rs256pk1.Encrypt(RS256(), rs256pk2.Public(), target)
	fmt.Println(base64.RawStdEncoding.EncodeToString(buf))

	fmt.Println("-----")
	buf2, err := rs256pk2.Decrypt(RS256(), rs256pk1.Public(), buf)
	fmt.Println(string(buf2), err)

	if !bytes.Equal(buf2, target) {
		t.Error("decrypt failed")
	}

	cspkcs1 := GetCipherSuiteFromAlg("RS256")
	cspkcs1.Padding = "PKCS1"

	target2 := []byte("Encrypt with RSA-PKCS1-GCM")
	buf3, _ := rs256pk1.Encrypt(cspkcs1, rs256pk2.Public(), target2)
	fmt.Println(base64.RawStdEncoding.EncodeToString(buf))

	fmt.Println("-----")
	buf4, err := rs256pk2.Decrypt(cspkcs1, rs256pk1.Public(), buf3)
	fmt.Println(string(buf4), err)

	if !bytes.Equal(buf4, target2) {
		t.Error("decrypt failed")
	}

}

func TestEncryptECDHGCM(t *testing.T) {

	fmt.Printf("Generate ECC PrivateKey 1 in JWK format.\n")
	rs256pk1, _ := GenerateKey("ES256")
	printInJSON(rs256pk1)

	eck := rs256pk1.(*ECPrivateKey)
	printInJSON((*ecdsa.PrivateKey)(eck))

	fmt.Printf("Generate ECC PrivateKey 2 in JWK format.\n")
	rs256pk2, _ := GenerateKey("ES256")
	printInJSON(rs256pk2)

	target := []byte("Encrypt with ECDH-GCM")
	buf, _ := rs256pk1.Encrypt(RS256(), rs256pk2.Public(), target)
	fmt.Println(base64.RawStdEncoding.EncodeToString(buf))

	fmt.Println("-----")
	buf2, err := rs256pk2.Decrypt(RS256(), rs256pk1.Public(), buf)
	fmt.Println(string(buf2), err)

	if !bytes.Equal(buf2, target) {
		t.Error("decrypt failed")
	}

}

func printInJSON(o interface{}) {
	oj, _ := json.MarshalIndent(o, "", "    ")
	fmt.Printf("%s\n\n", oj)
}
