package cry

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

const SECRET_LENGTH = 32
const SECRET_ENCRYPTED_LEN = 1024

var ErrUnexpectedSecretLen = errors.New("unexpected length of a symmetric key")

func EncryptAESEncodeHex(key, data []byte) (encryptedData string, err error) {
	if len(key) < SECRET_LENGTH {
		return "", ErrUnexpectedSecretLen
	}

	key = key[:32]

	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	data = aesAddPadding(data, c.BlockSize())

	mode := cipher.NewCBCEncrypter(c, key[:c.BlockSize()])

	buffer := make([]byte, len(data))

	mode.CryptBlocks(buffer, data)

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

	mode := cipher.NewCBCDecrypter(c, key[:c.BlockSize()])

	buffer := make([]byte, len(decoded))

	mode.CryptBlocks(buffer, []byte(decoded))

	buffer = aesRemovePadding(buffer)

	return string(buffer), nil
}

func aesAddPadding(data []byte, blockSize int) (paddedData []byte) {
	neededPadding := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(neededPadding)}, neededPadding)
	return append(data, padding...)
}

func aesRemovePadding(data []byte) []byte {
	return data[:(len(data) - int(data[len(data)-1]))]
}
