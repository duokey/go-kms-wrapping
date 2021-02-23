package duokeykms

import (
	"encoding/base64"

	"github.com/duokey/duokey-sdk-go/service/kms"
)

// Encrypt returns a base64 encoded string
func (k *mockKMS) Encrypt(input *kms.EncryptInput) (*kms.EncryptOutput, error) {

	b64encoded := make([]byte, base64.StdEncoding.EncodedLen(len(input.Payload)))
	base64.StdEncoding.Encode(b64encoded, input.Payload)

	r := &kms.EncryptOutput{}
	r.Result.KeyID = input.KeyID
	r.Result.Payload = b64encoded

	return r
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
	r.Result.KeyID = input.KeyID
	r.Result.Payload = b64encoded

	return r
}
