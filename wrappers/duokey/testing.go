package duokeykms

import (
	"context"
	"encoding/base64"

	"github.com/duokey/duokey-sdk-go/service/kms"
	"github.com/duokey/duokey-sdk-go/service/kms/kmsiface"
)

type mockKMS struct{}

// mockKMS implements the KMSAPI interface
var _ kmsiface.KMSAPI = (*mockKMS)(nil)

// NewMockWrapper returns a mock wrapper to test our code
func NewMockWrapper() *Wrapper {
	w := NewWrapper(nil)
	w.client = &mockKMS{}
	return w
}

// Encrypt returns a base64 encoded string
func (k *mockKMS) Encrypt(input *kms.EncryptInput) (*kms.EncryptOutput, error) {

	b64encoded := make([]byte, base64.StdEncoding.EncodedLen(len(input.Payload)))
	base64.StdEncoding.Encode(b64encoded, input.Payload)

	r := &kms.EncryptOutput{}
	r.Success = true
	r.Result.KeyID = input.KeyID
	r.Result.Payload = b64encoded

	return r, nil
}

// EncryptWithContext is the same operation as Encrypt. It is however possible
// to pass a non-nil context.
func (k *mockKMS) EncryptWithContext(_ context.Context, input *kms.EncryptInput) (*kms.EncryptOutput, error) {
	return k.Encrypt(input)
}

// Decrypt returns a decoded base64 string
func (k *mockKMS) Decrypt(input *kms.DecryptInput) (*kms.DecryptOutput, error) {

	maxLen := base64.StdEncoding.DecodedLen(len(input.Payload))
	b64decoded := make([]byte, maxLen)

	len, err := base64.StdEncoding.Decode(b64decoded, input.Payload)
	if err != nil {
		return nil, err
	}

	if len < maxLen {
		b64decoded = b64decoded[:len]
	}

	r := &kms.DecryptOutput{}
	r.Success = true
	r.Result.KeyID = input.KeyID
	r.Result.Payload = b64decoded

	return r, nil
}

// DecryptWithContext is the same operation as Decrypt. It is however possible
// to pass a non-nil context.
func (k *mockKMS) DecryptWithContext(_ context.Context, input *kms.DecryptInput) (*kms.DecryptOutput, error) {
	return k.Decrypt(input)
}
