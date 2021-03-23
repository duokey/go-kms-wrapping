package duokeykms

import (
	"context"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// This test executes real calls.
//
// To run this test, the following environmental variables need to be set:
//   - DUOKEY_ISSUER
//   - DUOKEY_CLIENT_ID
//   - DUOKEY_CLIENT_SECRET
//   - DUOKEY_VAULT_ID
//   - DUOKEY_KEY_ID
//   - DUOKEY_TENANT_ID
//   - DUOKEY_USERNAME
//   - DUOKEY_PASSWORD
//   - DUOKEY_SCOPE
//   - DUOKEY_BASE_URL
//   - DUOKEY_ENCRYPT_ROUTE
//   - DUOKEY_DECRYPT_ROUTE
func TestDuoKeyWrapper(t *testing.T) {

	// Get wrapper configuration from environment variables
	config := map[string]string{}
	w := NewWrapper(nil)
	if _, err := w.SetConfig(config); err != nil {
		t.Errorf("failed to create a new DuoKey wrapper: %w", err)
	}

	// Random plaintext
	plaintext := make([]byte, 512)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fail()
	}

	// Random tag for authenticated encryption
	aad := make([]byte, 16)
	if _, err := rand.Read(aad); err != nil {
		t.Fail()
	}

	// Generate an encryption key K, encrypt plaintext with K, and wrap K with DuoKey
	blob, err := w.Encrypt(context.Background(), plaintext, aad)
	if err != nil {
		t.Errorf("failed to encrypt the payload: %w", err)
	}

	// Does the encrypted blob contain the key ID?
	if blob.KeyInfo.KeyID != w.keyID {
		t.Errorf("unexpected key id in the encrypted blob: %s", blob.KeyInfo.KeyID)
	}

	// Unwrap K with Duokey and decrypt the ciphertext
	pt, err := w.Decrypt(context.Background(), blob, aad)
	if err != nil {
		t.Errorf("failed to decrypt the payload: %s", err.Error())
	}

	// We should obtain our original plaintext
	assert.Equal(t, plaintext, pt)
}

// This test executes real calls. The timeout is too short and an error is expected.
//
// To run this test, the following environmental variables need to be set:
//   - DUOKEY_ISSUER
//   - DUOKEY_CLIENT_ID
//   - DUOKEY_CLIENT_SECRET
//   - DUOKEY_VAULT_ID
//   - DUOKEY_KEY_ID
//   - DUOKEY_TENANT_ID
//   - DUOKEY_USERNAME
//   - DUOKEY_PASSWORD
//   - DUOKEY_SCOPE
//   - DUOKEY_BASE_URL
//   - DUOKEY_ENCRYPT_ROUTE
//   - DUOKEY_DECRYPT_ROUTE
func TestDuoKeyWrapperWithTimeout(t *testing.T) {

	// Get wrapper configuration from environment variables
	config := map[string]string{}
	w := NewWrapper(nil)
	if _, err := w.SetConfig(config); err != nil {
		t.Errorf("failed to create a new DuoKey wrapper: %s", err.Error())
	}

	// Random plaintext
	plaintext := make([]byte, 512)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fail()
	}

	// Random tag for authenticated encryption
	aad := make([]byte, 16)
	if _, err := rand.Read(aad); err != nil {
		t.Fail()
	}

	// Context with a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// Generate an encryption key K, encrypt plaintext with K, and wrap K with DuoKey
	_, err := w.Encrypt(ctx, plaintext, aad)
	if err == nil {
		t.Error("a timeout was expected")
	}

	msg := err.Error()
	assert.Contains(t, msg, "context deadline exceeded", "a timeout was expected")
}

// Checks that an error is triggered if a parameter is missing in the DuoKey configuration (provided as a map)
func TestSetConfigEnvVariable(t *testing.T) {
	testCases := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{
			name: "expected configuration",
			config: map[string]string{
				"DUOKEY_ISSUER":        "https://www.duokey.ch",
				"DUOKEY_CLIENT_ID":     "dke.cockpit",
				"DUOKEY_CLIENT_SECRET": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"DUOKEY_VAULT_ID":      "HSM",
				"DUOKEY_KEY_ID":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"DUOKEY_TENANT_ID":     "42",
				"DUOKEY_USERNAME":      "jane.doe",
				"DUOKEY_PASSWORD":      "s3crEt",
				"DUOKEY_SCOPE":         "vault-api",
				"DUOKEY_BASE_URL":      "https://www.duokey.ch",
				"DUOKEY_ENCRYPT_ROUTE": "vault/v1/encrypt",
				"DUOKEY_DECRYPT_ROUTE": "vault/v1/decrypt"},
			wantErr: false,
		},
		{
			name: "no issuer",
			config: map[string]string{
				"DUOKEY_CLIENT_ID":     "dke.cockpit",
				"DUOKEY_CLIENT_SECRET": "correcthorsebatterystaple",
				"DUOKEY_VAULT_ID":      "HSM",
				"DUOKEY_KEY_ID":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"DUOKEY_TENANT_ID":     "42",
				"DUOKEY_USERNAME":      "jane.doe",
				"DUOKEY_PASSWORD":      "s3crEt",
				"DUOKEY_SCOPE":         "vault-api",
				"DUOKEY_BASE_URL":      "https://www.duokey.ch",
				"DUOKEY_ENCRYPT_ROUTE": "vault/v1/encrypt",
				"DUOKEY_DECRYPT_ROUTE": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no client ID",
			config: map[string]string{
				"DUOKEY_ISSUER":        "https://www.duokey.ch",
				"DUOKEY_CLIENT_SECRET": "correcthorsebatterystaple",
				"DUOKEY_VAULT_ID":      "HSM",
				"DUOKEY_KEY_ID":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"DUOKEY_TENANT_ID":     "42",
				"DUOKEY_USERNAME":      "jane.doe",
				"DUOKEY_PASSWORD":      "s3crEt",
				"DUOKEY_SCOPE":         "vault-api",
				"DUOKEY_BASE_URL":      "https://www.duokey.ch",
				"DUOKEY_ENCRYPT_ROUTE": "vault/v1/encrypt",
				"DUOKEY_DECRYPT_ROUTE": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no client secret",
			config: map[string]string{
				"DUOKEY_ISSUER":        "https://www.duokey.ch",
				"DUOKEY_CLIENT_ID":     "dke.cockpit",
				"DUOKEY_VAULT_ID":      "HSM",
				"DUOKEY_KEY_ID":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"DUOKEY_TENANT_ID":     "42",
				"DUOKEY_USERNAME":      "jane.doe",
				"DUOKEY_PASSWORD":      "s3crEt",
				"DUOKEY_SCOPE":         "vault-api",
				"DUOKEY_BASE_URL":      "https://www.duokey.ch",
				"DUOKEY_ENCRYPT_ROUTE": "vault/v1/encrypt",
				"DUOKEY_DECRYPT_ROUTE": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no vault ID",
			config: map[string]string{
				"DUOKEY_ISSUER":        "https://www.duokey.ch",
				"DUOKEY_CLIENT_ID":     "dke.cockpit",
				"DUOKEY_CLIENT_SECRET": "correcthorsebatterystaple",
				"DUOKEY_KEY_ID":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"DUOKEY_TENANT_ID":     "42",
				"DUOKEY_USERNAME":      "jane.doe",
				"DUOKEY_PASSWORD":      "s3crEt",
				"DUOKEY_SCOPE":         "vault-api",
				"DUOKEY_BASE_URL":      "https://www.duokey.ch",
				"DUOKEY_ENCRYPT_ROUTE": "vault/v1/encrypt",
				"DUOKEY_DECRYPT_ROUTE": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no key ID",
			config: map[string]string{
				"DUOKEY_ISSUER":        "https://www.duokey.ch",
				"DUOKEY_CLIENT_ID":     "dke.cockpit",
				"DUOKEY_CLIENT_SECRET": "correcthorsebatterystaple",
				"DUOKEY_VAULT_ID":      "HSM",
				"DUOKEY_TENANT_ID":     "42",
				"DUOKEY_USERNAME":      "jane.doe",
				"DUOKEY_PASSWORD":      "s3crEt",
				"DUOKEY_SCOPE":         "vault-api",
				"DUOKEY_BASE_URL":      "https://www.duokey.ch",
				"DUOKEY_ENCRYPT_ROUTE": "vault/v1/encrypt",
				"DUOKEY_DECRYPT_ROUTE": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no tenant ID",
			config: map[string]string{
				"DUOKEY_ISSUER":        "https://www.duokey.ch",
				"DUOKEY_CLIENT_ID":     "dke.cockpit",
				"DUOKEY_CLIENT_SECRET": "correcthorsebatterystaple",
				"DUOKEY_VAULT_ID":      "HSM",
				"DUOKEY_KEY_ID":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"DUOKEY_USERNAME":      "jane.doe",
				"DUOKEY_PASSWORD":      "s3crEt",
				"DUOKEY_SCOPE":         "vault-api",
				"DUOKEY_BASE_URL":      "https://www.duokey.ch",
				"DUOKEY_ENCRYPT_ROUTE": "vault/v1/encrypt",
				"DUOKEY_DECRYPT_ROUTE": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no username",
			config: map[string]string{
				"DUOKEY_ISSUER":        "https://www.duokey.ch",
				"DUOKEY_CLIENT_ID":     "dke.cockpit",
				"DUOKEY_CLIENT_SECRET": "correcthorsebatterystaple",
				"DUOKEY_VAULT_ID":      "HSM",
				"DUOKEY_KEY_ID":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"DUOKEY_TENANT_ID":     "42",
				"DUOKEY_PASSWORD":      "s3crEt",
				"DUOKEY_SCOPE":         "vault-api",
				"DUOKEY_BASE_URL":      "https://www.duokey.ch",
				"DUOKEY_ENCRYPT_ROUTE": "vault/v1/encrypt",
				"DUOKEY_DECRYPT_ROUTE": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no password",
			config: map[string]string{
				"DUOKEY_ISSUER":        "https://www.duokey.ch",
				"DUOKEY_CLIENT_ID":     "dke.cockpit",
				"DUOKEY_CLIENT_SECRET": "correcthorsebatterystaple",
				"DUOKEY_VAULT_ID":      "HSM",
				"DUOKEY_KEY_ID":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"DUOKEY_TENANT_ID":     "42",
				"DUOKEY_USERNAME":      "jane.doe",
				"DUOKEY_SCOPE":         "vault-api",
				"DUOKEY_BASE_URL":      "https://www.duokey.ch",
				"DUOKEY_ENCRYPT_ROUTE": "vault/v1/encrypt",
				"DUOKEY_DECRYPT_ROUTE": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no scope",
			config: map[string]string{
				"DUOKEY_ISSUER":        "https://www.duokey.ch",
				"DUOKEY_CLIENT_ID":     "dke.cockpit",
				"DUOKEY_CLIENT_SECRET": "correcthorsebatterystaple",
				"DUOKEY_VAULT_ID":      "HSM",
				"DUOKEY_KEY_ID":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"DUOKEY_TENANT_ID":     "42",
				"DUOKEY_USERNAME":      "jane.doe",
				"DUOKEY_PASSWORD":      "s3crEt",
				"DUOKEY_BASE_URL":      "https://www.duokey.ch",
				"DUOKEY_ENCRYPT_ROUTE": "vault/v1/encrypt",
				"DUOKEY_DECRYPT_ROUTE": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no nase URL",
			config: map[string]string{
				"DUOKEY_ISSUER":        "https://www.duokey.ch",
				"DUOKEY_CLIENT_ID":     "dke.cockpit",
				"DUOKEY_CLIENT_SECRET": "correcthorsebatterystaple",
				"DUOKEY_VAULT_ID":      "HSM",
				"DUOKEY_KEY_ID":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"DUOKEY_TENANT_ID":     "42",
				"DUOKEY_USERNAME":      "jane.doe",
				"DUOKEY_PASSWORD":      "s3crEt",
				"DUOKEY_SCOPE":         "vault-api",
				"DUOKEY_ENCRYPT_ROUTE": "vault/v1/encrypt",
				"DUOKEY_DECRYPT_ROUTE": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no route for encryption",
			config: map[string]string{
				"DUOKEY_ISSUER":        "https://www.duokey.ch",
				"DUOKEY_CLIENT_ID":     "dke.cockpit",
				"DUOKEY_CLIENT_SECRET": "correcthorsebatterystaple",
				"DUOKEY_VAULT_ID":      "HSM",
				"DUOKEY_KEY_ID":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"DUOKEY_TENANT_ID":     "42",
				"DUOKEY_USERNAME":      "jane.doe",
				"DUOKEY_PASSWORD":      "s3crEt",
				"DUOKEY_SCOPE":         "vault-api",
				"DUOKEY_BASE_URL":      "https://www.duokey.ch",
				"DUOKEY_DECRYPT_ROUTE": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no route for decryption",
			config: map[string]string{
				"DUOKEY_ISSUER":        "https://www.duokey.ch",
				"DUOKEY_CLIENT_ID":     "dke.cockpit",
				"DUOKEY_CLIENT_SECRET": "correcthorsebatterystaple",
				"DUOKEY_VAULT_ID":      "HSM",
				"DUOKEY_KEY_ID":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"DUOKEY_TENANT_ID":     "42",
				"DUOKEY_USERNAME":      "jane.doe",
				"DUOKEY_PASSWORD":      "s3crEt",
				"DUOKEY_SCOPE":         "vault-api",
				"DUOKEY_BASE_URL":      "https://www.duokey.ch",
				"DUOKEY_ENCRYPT_ROUTE": "vault/v1/encrypt"},
			wantErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {

			w := NewMockWrapper()

			// Set all environment variables
			for key, value := range testCase.config {
				os.Setenv(key, value)
			}

			config := map[string]string{}
			_, err := w.SetConfig(config)
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

			// Unset environment variables befor
			for key := range testCase.config {
				os.Unsetenv(key)
			}
		})
	}
}

// Checks that an error is triggered if a parameter is missing in the DuoKey configuration (provided as environmental variables)
func TestSetConfig(t *testing.T) {

	testCases := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{
			name: "expected configuration",
			config: map[string]string{
				"issuer":        "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple", // See https://xkcd.com/936/
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"base_url":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: false,
		},
		{
			name: "no issuer",
			config: map[string]string{
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple",
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"base_url":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no client ID",
			config: map[string]string{
				"issuer":        "https://www.duokey.ch",
				"client_secret": "correcthorsebatterystaple",
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"base_url":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no client secret",
			config: map[string]string{
				"issuer":        "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"base_url":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no vault id",
			config: map[string]string{
				"issuer":        "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"base_url":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no key id",
			config: map[string]string{
				"issuer":        "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple",
				"vault_id":      "HSM",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"base_url":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no tenant id",
			config: map[string]string{
				"issuer":        "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple",
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"base_url":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "tenant id is not an uint32 1/2",
			config: map[string]string{
				"issuer":        "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple",
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "twelve",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"base_url":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "tenant id is not an uint32",
			config: map[string]string{
				"issuer":        "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple",
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "-1",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"base_url":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no username",
			config: map[string]string{
				"issuer":        "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple",
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"base_url":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no password",
			config: map[string]string{
				"issuer":        "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple",
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"scope":         "vault-api",
				"base_url":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no scope",
			config: map[string]string{
				"issuer":        "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple",
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"base_url":      "https://www.duokey.ch",
				"encrypt_route": "vault/v1/encrypt",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no base URL",
			config: map[string]string{
				"issuer":        "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple",
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
			config: map[string]string{
				"issuer":        "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple",
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"base_url":      "https://www.duokey.ch",
				"decrypt_route": "vault/v1/decrypt"},
			wantErr: true,
		},
		{
			name: "no route for decryption",
			config: map[string]string{
				"issuer":        "https://www.duokey.ch",
				"client_id":     "dke.cockpit",
				"client_secret": "correcthorsebatterystaple",
				"vault_id":      "HSM",
				"key_id":        "efbfff7c-fa48-4aba-bf48-6d3d832df292",
				"tenant_id":     "42",
				"username":      "jane.doe",
				"password":      "s3crEt",
				"scope":         "vault-api",
				"base_url":      "https://www.duokey.ch",
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

// This test calls a mock service
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
	blob, err := w.Encrypt(context.Background(), plaintext, aad)
	if err != nil {
		t.Errorf("failed to encrypt the payload: %w", err)
	}

	// Does the encrypted blob contain the key ID?
	if blob.KeyInfo.KeyID != w.keyID {
		t.Errorf("unexpected key id in the encrypted blob: %s", blob.KeyInfo.KeyID)
	}

	// Unwrap K with our mock service and decrypt the ciphertext
	pt, err := w.Decrypt(context.Background(), blob, aad)
	if err != nil {
		t.Errorf("failed to decrypt the payload: %w", err)
	}

	// We should obtain our original plaintext
	assert.Equal(t, plaintext, pt)
}
