package cry

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

var ErrBadKey = errors.New("failed to parse key")

func GenPrivKey() (privateKey *rsa.PrivateKey, err error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

func PubKeyToPEM(pubKey *rsa.PublicKey) (pemEncoded string, err error) {
	spkiDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	spkiPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: spkiDER,
	})
	return string(spkiPEM), nil
}

func PrivKeyToPEM(privKey *rsa.PrivateKey) (pemEncoded string, err error) {
	spkiDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return "", err
	}
	spkiPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: spkiDER,
	})
	return string(spkiPEM), nil
}

func ImportPrivKeyPEM(spkiPEM []byte) (privKey *rsa.PrivateKey, err error) {
	body, _ := pem.Decode(spkiPEM)
	tempPrivKey, err := x509.ParsePKCS8PrivateKey(body.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := tempPrivKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrBadKey
	}
	return rsaKey, nil
}

func ImportPubKeyPEM(spkiPEM []byte) (pubKey *rsa.PublicKey, err error) {
	body, _ := pem.Decode(spkiPEM)
	tempPubKey, err := x509.ParsePKIXPublicKey(body.Bytes)
	if err != nil {
		return nil, err
	}
	pubKey, ok := tempPubKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrBadKey
	}
	return pubKey, nil
}
func EncryptRSAOAEPEncodeHex(key rsa.PublicKey, data string) (encryptedData string, err error) {
	label := []byte("OAEP Encrypted")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key, []byte(data), label)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ciphertext), nil
}

func DecryptRSAOAEPDecodeHex(privKey rsa.PrivateKey, encryptedData string) (data string, err error) {
	ct, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	label := []byte("OAEP Encrypted")
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &privKey, ct, label)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
