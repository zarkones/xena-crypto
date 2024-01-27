package cry

import (
	"testing"
)

func TestEncryption(t *testing.T) {
	privKey, err := GenPrivKey()
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	secret, err := GenSecret()
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	encrypted, err := EncryptRSAOAEPEncodeHex(privKey.PublicKey, string(secret))
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	if len(encrypted) != SECRET_ENCRYPTED_LEN {
		t.Log("generated secret when encrypted has an unexpected length of:", len(encrypted))
		t.FailNow()
	}
}
