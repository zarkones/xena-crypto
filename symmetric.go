package cry

import (
	"crypto/aes"
	"encoding/hex"
)

func EncryptAESEncodeHex(key, data []byte) (encryptedData string, err error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	buffer := make([]byte, len(data))

	c.Encrypt(buffer, data)

	return hex.EncodeToString(buffer), nil
}

func DecryptAESDecodeHex(key []byte, encryptedData string) (data string, err error) {
	decoded, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	buffer := make([]byte, len(decoded))

	c.Decrypt(buffer, decoded)

	return string(buffer), nil
}
