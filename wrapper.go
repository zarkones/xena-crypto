package cry

import (
	"crypto/rsa"
	"errors"
)

var ErrUnexpectedDataLen = errors.New("unexpected length of the data")

func SecureWrap(pubKey *rsa.PublicKey, data string) (string, error) {
	secret, err := GenSecret()
	if err != nil {
		return "", err
	}
	encryptedData, err := EncryptAESEncodeHex(secret[:32], []byte(data))
	if err != nil {
		return "", err
	}
	encryptedSecret, err := EncryptRSAOAEPEncodeHex(*pubKey, string(secret))
	if err != nil {
		return "", err
	}
	return encryptedSecret + encryptedData, nil
}

func SecureUnwrap(privKey *rsa.PrivateKey, encryptedData string) (string, error) {
	if len(encryptedData) <= SECRET_ENCRYPTED_LEN {
		return "", ErrUnexpectedDataLen
	}
	encryptedSecret := encryptedData[:SECRET_ENCRYPTED_LEN]
	secret, err := DecryptRSAOAEPDecodeHex(*privKey, encryptedSecret)
	if err != nil {
		return "", err
	}
	decryptedData, err := DecryptAESDecodeHex([]byte(secret), encryptedData[SECRET_ENCRYPTED_LEN:])
	if err != nil {
		return "", err
	}
	return decryptedData, nil
}
