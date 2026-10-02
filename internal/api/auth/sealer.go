package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// MinSecretLen is the minimum length of the session secret.
const MinSecretLen = 32

var errInvalidSeal = errors.New("invalid sealed value")

// sealer encrypts and authenticates small JSON values with AES-256-GCM. The
// key is derived from the configured secret with HKDF-SHA256. The cookie name
// is bound as additional data so a value minted for one cookie cannot be
// replayed as another (e.g. the login-transaction cookie as a session).
type sealer struct {
	aead cipher.AEAD
	now  func() time.Time
}

func newSealer(secret string, now func() time.Time) (*sealer, error) {
	if len(secret) < MinSecretLen {
		return nil, fmt.Errorf("session secret must be at least %d bytes", MinSecretLen)
	}
	key, err := hkdf.Key(sha256.New, []byte(secret), nil, "deckard session cookie v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{aead: aead, now: now}, nil
}

type envelope struct {
	Exp int64           `json:"exp"`
	Val json.RawMessage `json:"val"`
}

func (s *sealer) seal(name string, v any, ttl time.Duration) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	pt, err := json.Marshal(envelope{Exp: s.now().Add(ttl).Unix(), Val: raw})
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := s.aead.Seal(nonce, nonce, pt, []byte(name))
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

// open decrypts, verifies the tag, checks expiry and unmarshals into v.
func (s *sealer) open(name, sealed string, v any) error {
	ct, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(ct) < s.aead.NonceSize()+s.aead.Overhead() {
		return errInvalidSeal
	}
	pt, err := s.aead.Open(nil, ct[:s.aead.NonceSize()], ct[s.aead.NonceSize():], []byte(name))
	if err != nil {
		return errInvalidSeal
	}
	var env envelope
	if err := json.Unmarshal(pt, &env); err != nil {
		return errInvalidSeal
	}
	if !s.now().Before(time.Unix(env.Exp, 0)) {
		return errors.New("sealed value expired")
	}
	return json.Unmarshal(env.Val, v)
}
