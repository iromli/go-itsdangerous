package itsdangerous

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"hash"
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

type HMACAlgorithm struct {
	DigestMethod Hash
}

func (h *HMACAlgorithm) GetSignature(key, value string) string {
	mac := hmac.New(h.DigestMethod, []byte(key))
	mac.Write([]byte(value))
	return string(mac.Sum(nil))
}

func (h *HMACAlgorithm) VerifySignature(key, value, sig string) bool {
	eq := subtle.ConstantTimeCompare([]byte(sig), []byte(h.GetSignature(key, value)))
	return eq == 1
}

type Signer struct {
	SecretKey     string
	Sep           string
	Salt          string
	KeyDerivation string
	DigestMethod  Hash
	Algorithm     HMACAlgorithm
}

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

func (s *Signer) GetSignature(value string) string {
	key, _ := s.DeriveKey()
	sig := s.Algorithm.GetSignature(key, value)
	return base64Encode(sig)
}

func (s *Signer) VerifySignature(value, sig string) bool {
	key, _ := s.DeriveKey()
	signed := base64Decode(sig)
	return s.Algorithm.VerifySignature(key, value, signed)
}

func (s *Signer) Sign(value string) string {
	return value + s.Sep + s.GetSignature(value)
}

func (s *Signer) Unsign(signed string) (string, error) {
	p := strings.SplitN(signed, s.Sep, 2)
	if s.VerifySignature(p[0], p[1]) {
		return p[0], nil
	}
	return "", errors.New("Signature does not match")
}

func NewSigner(secretKey, salt, sep, keyDerivation string, digestMethod Hash) Signer {

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
	return Signer{
		SecretKey:     secretKey,
		Salt:          salt,
		Sep:           sep,
		KeyDerivation: keyDerivation,
		DigestMethod:  digestMethod,
		Algorithm:     HMACAlgorithm{DigestMethod: digestMethod},
	}
}
