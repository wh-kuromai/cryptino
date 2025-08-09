package cryptino

import (
	"encoding/base64"
	"strings"
)

func QTPEncrypt(secret PrivateKey, remote PublicKey, msg []byte) (string, error) {
	buf, err := secret.Encrypt(ES256(), remote, msg)
	if err != nil {
		return "", err
	}

	pub := secret.Public().MarshalSSHWire()
	return base64.RawURLEncoding.EncodeToString(pub) + "." + base64.RawURLEncoding.EncodeToString(buf), nil
}

func QTPDecrypt(secret PrivateKey, msg string) (PublicKey, []byte, error) {
	token := strings.Split(msg, ".")
	remotebuf, err := base64.RawURLEncoding.DecodeString(token[0])
	if err != nil {
		return nil, nil, err
	}

	remote, err := UnmarshalSSHWirePublicKey(remotebuf)
	if err != nil {
		return nil, nil, err
	}

	msgbuf, err := base64.RawURLEncoding.DecodeString(token[1])
	if err != nil {
		return nil, nil, err
	}

	buf, err := secret.Decrypt(ES256(), remote, msgbuf)
	if err != nil {
		return nil, nil, err
	}

	return remote, buf, nil
}
