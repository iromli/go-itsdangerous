package itsdangerous

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"hash"
	"log"
	"strings"
)

type Hash func() hash.Hash

func base64Encode(sig string) string {
	s := base64.URLEncoding.EncodeToString([]byte(sig))
	return strings.Trim(s, "=")
}

func base64Decode(value string) string {
	sig, _ := base64.URLEncoding.DecodeString(value)
	return string(sig) + strings.Repeat("=", len(sig)%4)
}

type SigningAlgorithm interface {
	GetSignature(key, value string) string
	VerifySignature(key, value, sig string) bool
}

// This struct provides signature generation using HMACs.
type HMACAlgorithm struct {
	DigestMethod Hash
}

// Returns the signature for the given key and value.
func (a *HMACAlgorithm) GetSignature(key, value string) string {
	h := hmac.New(a.DigestMethod, []byte(key))
	h.Write([]byte(value))
	return string(h.Sum(nil))
}

// Verifies the given signature matches the expected signature.
func (a *HMACAlgorithm) VerifySignature(key, value, sig string) bool {
	eq := subtle.ConstantTimeCompare([]byte(sig), []byte(a.GetSignature(key, value)))
	return eq == 1
}

// This struct provides an algorithm that does not perform any
// signing and returns an empty signature.
type NoneAlgorithm struct {
	HMACAlgorithm
}

// Returns the signature for the given key and value.
func (a *NoneAlgorithm) GetSignature(key, value string) string {
	return ""
}

type Signer struct {
	SecretKey     string
	Sep           string
	Salt          string
	KeyDerivation string
	DigestMethod  Hash
	Algorithm     SigningAlgorithm
}

// This method is called to derive the key.  If you're unhappy with
// the default key derivation choices you can override them here.
// Keep in mind that the key derivation in itsdangerous is not intended
// to be used as a security method to make a complex key out of a short
// password.  Instead you should use large random secret keys.
func (s *Signer) DeriveKey() (string, error) {
	var key string
	var err error

	switch s.KeyDerivation {
	case "concat":
		h := s.DigestMethod()
		h.Write([]byte(s.Salt + s.SecretKey))
		key, err = string(h.Sum(nil)), err
	case "django-concat":
		h := s.DigestMethod()
		h.Write([]byte(s.Salt + "signer" + s.SecretKey))
		key, err = string(h.Sum(nil)), nil
	case "hmac":
		h := hmac.New(s.DigestMethod, []byte(s.SecretKey))
		h.Write([]byte(s.Salt))
		key, err = string(h.Sum(nil)), nil
	case "none":
		key, err = s.SecretKey, nil
	default:
		key, err = "", errors.New("Unknown key derivation method")
	}
	return key, err
}

// Returns the signature for the given value.
func (s *Signer) GetSignature(value string) string {
	key, err := s.DeriveKey()
	if err != nil {
		log.Fatal(err)
	}
	sig := s.Algorithm.GetSignature(key, value)
	return base64Encode(sig)
}

// Verifies the signature for the given value.
func (s *Signer) VerifySignature(value, sig string) bool {
	key, err := s.DeriveKey()
	if err != nil {
		log.Fatal(err)
	}
	signed := base64Decode(sig)
	return s.Algorithm.VerifySignature(key, value, signed)
}

// Signs the given string.
func (s *Signer) Sign(value string) string {
	return value + s.Sep + s.GetSignature(value)
}

// Unsigns the given string.
func (s *Signer) Unsign(signed string) (string, error) {
	p := strings.SplitN(signed, s.Sep, 2)
	if s.VerifySignature(p[0], p[1]) {
		return p[0], nil
	}
	return "", errors.New("Signature does not match")
}

func NewSigner(secretKey, salt, sep, keyDerivation string, digestMethod Hash, algorithm SigningAlgorithm) *Signer {
	if salt == "" {
		salt = "itsdangerous.Signer"
	}
	if sep == "" {
		sep = "."
	}
	if keyDerivation == "" {
		keyDerivation = "django-concat"
	}
	if digestMethod == nil {
		digestMethod = sha1.New
	}
	if algorithm == nil {
		algorithm = &HMACAlgorithm{DigestMethod: digestMethod}
	}
	return &Signer{
		SecretKey:     secretKey,
		Salt:          salt,
		Sep:           sep,
		KeyDerivation: keyDerivation,
		DigestMethod:  digestMethod,
		Algorithm:     algorithm,
	}
}
