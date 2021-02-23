package duokeykms

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"

	"github.com/duokey/duokey-sdk-go/duokey/credentials"
	"github.com/duokey/duokey-sdk-go/duokey/restapi"
	"github.com/duokey/duokey-sdk-go/service/kms"
	"github.com/duokey/duokey-sdk-go/service/kms/kmsiface"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// Wrapper is a Wrapper that uses DuoKey KMS
type Wrapper struct {
	issuer       string
	clientID     string
	clientSecret string
	vaultID      string
	keyID        string
	ussername    string
	password     string
	scope        string
	tenandID     uint32

	// Routes
	basePath   string
	kmsEncrypt string
	kmsDecrypt string

	client kmsiface.KMSAPI

	currentKeyID *atomic.Value
}

// Ensure that we are implementing the wrapping.Wrapper interface
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new DuoKey wrapper
func NewWrapper(opts *wrapping.WrapperOptions) *Wrapper {
	if opts == nil {
		opts = new(wrapping.WrapperOptions)
	}
	k := &Wrapper{
		currentKeyID: new(atomic.Value),
	}
	k.currentKeyID.Store("")
	return k
}

// SetConfig retrieves DuoKey settings from environment variables or a configuration file.
// Returns a map that holds non-sensitive configuration info.
func (k *Wrapper) SetConfig(config map[string]string) (map[string]string, error) {
	if config == nil {
		config = map[string]string{}
	}

	// Check and set the issuer
	switch {
	case os.Getenv("DUOKEY_ISSUER") != "":
		k.issuer = os.Getenv("DUOKEY_ISSUER")
	case config["issuer"] != "":
		k.issuer = config["issuer"]
	default:
		return nil, errors.New("issuer is required")
	}

	// Check and set the client ID
	switch {
	case os.Getenv("DUOKEY_CLIENT_ID") != "":
		k.clientID = os.Getenv("DUOKEY_CLIENT_ID")
	case config["client_id"] != "":
		k.clientID = config["client_id"]
	default:
		return nil, errors.New("client ID is required")
	}

	// Check and set the client secret
	switch {
	case os.Getenv("DUOKEY_CLIENT_SECRET") != "":
		k.clientSecret = os.Getenv("DUOKEY_CLIENT_SECRET")
	case config["client_secret"] != "":
		k.clientSecret = config["client_secret"]
	default:
		return nil, errors.New("client secret is required")
	}

	// Check and set the vault ID
	switch {
	case os.Getenv("DUOKEY_VAULT_ID") != "":
		k.vaultID = os.Getenv("DUOKEY_VAULT_ID")
	case config["vault_id"] != "":
		k.vaultID = config["vault_id"]
	default:
		return nil, errors.New("vault ID is required")
	}

	// Check and set the key ID
	switch {
	case os.Getenv("DUOKEY_KEY_ID") != "":
		k.keyID = os.Getenv("DUOKEY_KEY_ID")
	case config["key_id"] != "":
		k.keyID = config["key_id"]
	default:
		return nil, errors.New("key ID is required")
	}

	// Check and set the tenant ID
	var tid string
	switch {
	case os.Getenv("DUOKEY_TENANT_ID") != "":
		tid = os.Getenv("DUOKEY_TENANT_ID")
	case config["tenant_id"] != "":
		tid = config["tenant_id"]
	default:
		return nil, errors.New("tenant ID is required")
	}

	value, err := strconv.ParseUint(tid, 10, 32)
	if err != nil {
		return nil, errors.New("tenant ID must be an uint32 value")
	}

	k.tenandID = uint32(value)

	// Check and set the username
	switch {
	case os.Getenv("DUOKEY_USERNAME") != "":
		k.ussername = os.Getenv("DUOKEY_USERNAME")
	case config["username"] != "":
		k.ussername = config["username"]
	default:
		return nil, errors.New("username is required")
	}

	// Check and set the password
	switch {
	case os.Getenv("DUOKEY_PASSWORD") != "":
		k.password = os.Getenv("DUOKEY_PASSWORD")
	case config["password"] != "":
		k.password = config["password"]
	default:
		return nil, errors.New("password is required")
	}

	// Check and set the scope
	switch {
	case os.Getenv("DUOKEY_SCOPE") != "":
		k.scope = os.Getenv("DUOKEY_SCOPE")
	case config["scope"] != "":
		k.scope = config["scope"]
	default:
		return nil, errors.New("scope is required")
	}

	// Check and set the base path
	switch {
	case os.Getenv("DUOKEY_BASE_PATH") != "":
		k.basePath = os.Getenv("DUOKEY_BASE_PATH")
	case config["basepath"] != "":
		k.basePath = config["basepath"]
	default:
		return nil, errors.New("base path is required")
	}

	// Check and set the encrypt route
	switch {
	case os.Getenv("DUOKEY_ENCRYPT_ROUTE") != "":
		k.kmsEncrypt = os.Getenv("DUOKEY_ENCRYPT_ROUTE")
	case config["encryptroute"] != "":
		k.kmsEncrypt = config["encryptroute"]
	default:
		return nil, errors.New("route for encryption is required")
	}

	// Check and set the encrypt route
	switch {
	case os.Getenv("DUOKEY_DECRYPT_ROUTE") != "":
		k.kmsDecrypt = os.Getenv("DUOKEY_DECRYPT_ROUTE")
	case config["decryptroute"] != "":
		k.kmsDecrypt = config["decryptroute"]
	default:
		return nil, errors.New("route for decryption is required")
	}

	if k.client == nil {
		client, err := k.getDuoKeyClient()
		if err != nil {
			return nil, fmt.Errorf("error initializing a DuoKey Vault wrapper client: %w", err)
		}
		k.client = client
	}

	// Map that holds non-sensitive configuration info
	wrappingInfo := make(map[string]string)
	wrappingInfo["key_id"] = k.keyID
	wrappingInfo["vault_id"] = k.vaultID
	wrappingInfo["tenant_id"] = fmt.Sprint(k.tenandID)

	return wrappingInfo, nil
}

// Encrypt is used to encrypt the master key using the the DuoKey service.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(_ context.Context, plaintext, aad []byte) (blob *wrapping.EncryptedBlobInfo, err error) {

	if plaintext == nil {
		return nil, fmt.Errorf("plaintext for encryption is nil")
	}

	env, err := wrapping.NewEnvelope(nil).Encrypt(plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	input := &kms.EncryptInput{
		KeyID: k.keyID,
		VaultID: k.vaultID,
		Payload: env.Key,
	}

	output, err := k.client.Encrypt(input)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	// Store the current key ID
	keyID := output.Result.KeyID
	k.currentKeyID.Store(keyID)

	ret := &wrapping.EncryptedBlobInfo{
		Ciphertext: env.Ciphertext,
		IV:         env.IV,
		KeyInfo: &wrapping.KeyInfo{
			KeyID:      keyID,
			WrappedKey: output.Result.Payload,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (k *Wrapper) Decrypt(_ context.Context, in *wrapping.EncryptedBlobInfo, aad []byte) (pt []byte, err error) {

	if in == nil {
		return nil, fmt.Errorf("input for decryption is nil")
	}

	if in.KeyInfo == nil {
		return nil, errors.New("key info is nil")
	}

	input := &kms.DecryptInput{
		KeyID: in.KeyInfo.KeyID,
		VaultID: k.vaultID,
		Payload: in.KeyInfo.WrappedKey,
	}

	// Decrypt the wrapped key with DuoKey
	output, err := k.client.Decrypt(input)
	if err != nil {
		return nil, fmt.Errorf("error decrypting key: %w", err)
	}

	// Decrypt the envelope
	envInfo := &wrapping.EnvelopeInfo{
		Key:        output.Result.Payload,
		IV:         in.IV,
		Ciphertext: in.Ciphertext,
	}

	plaintext, err := wrapping.NewEnvelope(nil).Decrypt(envInfo, aad)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return plaintext, nil
}

// Init is called during core.Initialize. No-op at the moment.
func (k *Wrapper) Init(_ context.Context) error {
	return nil
}

// Finalize is called during shutdown. This is a no-op since
// the DuoKey wrapper doesn't require any cleanup.
func (k *Wrapper) Finalize(_ context.Context) error {
	return nil
}

// Type returns the type for this particular wrapper implementation
func (k *Wrapper) Type() string {
	return wrapping.DuoKeyKMS
}

// KeyID returns the last known key id
func (k *Wrapper) KeyID() string {
	return k.currentKeyID.Load().(string)
}

// HMACKeyID returns the last known HMAC key id
func (k *Wrapper) HMACKeyID() string {
	return ""
}

// GetDuoKeyClient returns an instance of the DuoKey KMS client
func (k *Wrapper) getDuoKeyClient() (*kms.KMS, error) {

	credentials := credentials.Config{}
	credentials.Issuer = k.issuer
	credentials.ClientID = k.clientID
	credentials.ClientSecret = k.clientSecret
	credentials.VaultID = k.vaultID
	credentials.UserName = k.ussername
	credentials.Password = k.password
	credentials.Scope = k.scope
	credentials.TenantID = k.tenandID

	routes := restapi.Config{}
	routes.BasePath = k.basePath
	routes.KMSEncrypt = k.kmsEncrypt
	routes.KMSDecrypt = k.kmsDecrypt

	client, err := kms.New(credentials, routes)
	if err != nil {
		return nil, fmt.Errorf("error initializing DuoKey client: %w", err)
	}

	return client, nil
}
