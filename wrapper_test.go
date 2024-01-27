package cry

import (
	"testing"
)

func TestWrapping(t *testing.T) {
	payload := "hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world, hello world"
	privKey, err := GenPrivKey()
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	wrapped, err := SecureWrap(&privKey.PublicKey, payload)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	unwrapped, err := SecureUnwrap(privKey, wrapped)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	if payload != unwrapped {
		t.Log("payload does not match the payload that was encrypted and then decrypted")
	}
}
