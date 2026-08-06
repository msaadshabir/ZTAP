package audit

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
)

// Signer provides cryptographic signing for audit entries.
type Signer interface {
	Sign(data []byte) ([]byte, error)
	Algorithm() string
	KeyID() string
}

// Verifier provides cryptographic verification for audit entries.
type Verifier interface {
	Verify(data []byte, sig []byte) (bool, error)
	Algorithm() string
	KeyID() string
}

// Ed25519Signer implements Signer using Ed25519.
type Ed25519Signer struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	keyID      string
}

func NewEd25519Signer(privateKey ed25519.PrivateKey, keyID string) *Ed25519Signer {
	return &Ed25519Signer{
		PrivateKey: privateKey,
		PublicKey:  privateKey.Public().(ed25519.PublicKey),
		keyID:      keyID,
	}
}

func (s *Ed25519Signer) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.PrivateKey, data), nil
}

func (s *Ed25519Signer) Algorithm() string { return "ed25519" }
func (s *Ed25519Signer) KeyID() string     { return s.keyID }

// Ed25519Verifier implements Verifier using Ed25519.
type Ed25519Verifier struct {
	PublicKey ed25519.PublicKey
	keyID     string
}

func NewEd25519Verifier(publicKey ed25519.PublicKey, keyID string) *Ed25519Verifier {
	return &Ed25519Verifier{PublicKey: publicKey, keyID: keyID}
}

func (v *Ed25519Verifier) Verify(data []byte, sig []byte) (bool, error) {
	return ed25519.Verify(v.PublicKey, data, sig), nil
}

func (v *Ed25519Verifier) Algorithm() string { return "ed25519" }
func (v *Ed25519Verifier) KeyID() string     { return v.keyID }

// HMACSigner implements Signer using HMAC-SHA256.
type HMACSigner struct {
	key   []byte
	keyID string
}

func NewHMACSigner(key []byte, keyID string) *HMACSigner {
	return &HMACSigner{key: key, keyID: keyID}
}

func NewHMACVerifier(key []byte, keyID string) *HMACVerifier {
	return &HMACVerifier{key: key, keyID: keyID}
}

func (s *HMACSigner) Sign(data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(data)
	return mac.Sum(nil), nil
}

func (s *HMACSigner) Algorithm() string { return "hmac-sha256" }
func (s *HMACSigner) KeyID() string     { return s.keyID }

// HMACVerifier implements Verifier using HMAC-SHA256.
type HMACVerifier struct {
	key   []byte
	keyID string
}

func (v *HMACVerifier) Verify(data []byte, sig []byte) (bool, error) {
	mac := hmac.New(sha256.New, v.key)
	_, _ = mac.Write(data)
	expected := mac.Sum(nil)
	return hmac.Equal(expected, sig), nil
}

func (v *HMACVerifier) Algorithm() string { return "hmac-sha256" }
func (v *HMACVerifier) KeyID() string     { return v.keyID }
