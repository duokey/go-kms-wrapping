package duokeykms

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSetConfig(t *testing.T) {

	testCases := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{
			name: "expected configuration",
			config: map[string]string{"issuer": "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"basepath":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: false,
		},
		{
			name: "no client ID",
			config: map[string]string{"issuer": "https://www.duokey.ch",
				"client_secret": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"basepath":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no client secret",
			config: map[string]string{"issuer": "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"basepath":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no vault id",
			config: map[string]string{"issuer": "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"basepath":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no key id",
			config: map[string]string{"issuer": "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"vault_id":      "HSM",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"basepath":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no tenant id",
			config: map[string]string{"issuer": "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"basepath":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "tenant id is not an uint32 1/2",
			config: map[string]string{"issuer": "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "twelve",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"basepath":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "tenant id is not an uint32",
			config: map[string]string{"issuer": "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "-1",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"basepath":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no username",
			config: map[string]string{"issuer": "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"basepath":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no password",
			config: map[string]string{"issuer": "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"scope":         "vault-api",
				"basepath":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no scope",
			config: map[string]string{"issuer": "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"basepath":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no basepath",
			config: map[string]string{"issuer": "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no route for encryption",
			config: map[string]string{"issuer": "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"basepath":      "https://www.duokey.ch",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no route for decryption",
			config: map[string]string{"issuer": "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"basepath":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt"},
			wantErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			w := NewMockWrapper()
			_, err := w.SetConfig(testCase.config)
			if err == nil {
				if testCase.wantErr {
					// Our test case should trigger an error
					t.Error("error expected")
				}
			} else {
				if !testCase.wantErr {
					// Our test shouldn't trigger an error
					t.Errorf("unexpected error: %s", err.Error())
				}
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	var err error

	// Mock service (no call to DuoKey REST API)
	w := NewMockWrapper()
	w.keyID = "test"

	// Random plaintext
	plaintext := make([]byte, 64)
	_, err = rand.Read(plaintext)
	if err != nil {
		t.Fail()
	}

	// Random tag for authenticated encryption
	aad := make([]byte, 16)
	_, err = rand.Read(aad)
	if err != nil {
		t.Fail()
	}

	// Generate an encryption key K, encrypt plaintext with K, and wrap K with our
	// mock service
	blob, err := w.Encrypt(nil, plaintext, aad)
	if err != nil {
		t.Errorf("failed to encrypt the payload: %s", err.Error())
	}

	// Does the encrypted blob contain the key ID?
	if blob.KeyInfo.KeyID != w.keyID {
		t.Errorf("unexpected key id in the encrypted blob: %s", blob.KeyInfo.KeyID)
	}

	// Unwrap K with our mock service and decrypt the ciphertext
	pt, err := w.Decrypt(nil, blob, aad)
	if err != nil {
		t.Errorf("failed to decrypt the payload: %s", err.Error())
	}

	// We should obtain our original plaintext
	if bytes.Compare(pt, plaintext) != 0 {
		t.Fail()
	}
}
