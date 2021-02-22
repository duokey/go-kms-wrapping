package duokeykms

import (
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
