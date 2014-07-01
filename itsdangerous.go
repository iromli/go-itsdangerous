package itsdangerous

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"log"
	"strings"
	"time"
)

// 2011/01/01 in UTC
const EPOCH = 1293840000

// Encodes a single string. The resulting string is safe for putting into URLs.
func base64Encode(sig string) string {
	s := base64.URLEncoding.EncodeToString([]byte(sig))
	return strings.Trim(s, "=")
}

// Decodes a single string.
func base64Decode(value string) string {
	sig, err := base64.URLEncoding.DecodeString(value + strings.Repeat("=", len(value)%4))
	if err != nil {
		log.Fatal(err)
	}
	return string(sig)
}

// Returns the current timestamp.  This implementation returns the
// seconds since 1/1/2011.
func getTimestamp() uint32 {
	return uint32(time.Now().Unix() - EPOCH)
}

type SigningAlgorithm interface {
	GetSignature(key, value string) string
	VerifySignature(key, value, sig string) bool
}

// This struct provides signature generation using HMACs.
type HMACAlgorithm struct {
	DigestMethod hash.Hash
}

// Returns the signature for the given key and value.
func (a *HMACAlgorithm) GetSignature(key, value string) string {
	h := hmac.New(func() hash.Hash { return a.DigestMethod }, []byte(key))
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
	DigestMethod  hash.Hash
	Algorithm     SigningAlgorithm
}

// Derives the key. Keep in mind that the key derivation in itsdangerous is not intended
// to be used as a security method to make a complex key out of a short password.
// Instead you should use large random secret keys.
func (s *Signer) DeriveKey() (string, error) {
	var key string
	var err error

	switch s.KeyDerivation {
	case "concat":
		h := s.DigestMethod
		h.Write([]byte(s.Salt + s.SecretKey))
		key, err = string(h.Sum(nil)), err
	case "django-concat":
		h := s.DigestMethod
		h.Write([]byte(s.Salt + "signer" + s.SecretKey))
		key, err = string(h.Sum(nil)), nil
	case "hmac":
		h := hmac.New(func() hash.Hash { return s.DigestMethod }, []byte(s.SecretKey))
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
	if !strings.Contains(signed, s.Sep) {
		return "", errors.New(fmt.Sprintf("No %s found in value", s.Sep))
	}

	li := strings.LastIndex(signed, s.Sep)
	value, sig := signed[:li], signed[li+len(s.Sep):]

	if s.VerifySignature(value, sig) {
		return value, nil
	}
	return "", errors.New(fmt.Sprintf("Signature %s does not match", sig))
}

func NewSigner(secret, salt, sep, derivation string, digest hash.Hash, algo SigningAlgorithm) *Signer {
	if salt == "" {
		salt = "itsdangerous.Signer"
	}
	if sep == "" {
		sep = "."
	}
	if derivation == "" {
		derivation = "django-concat"
	}
	if digest == nil {
		digest = sha1.New()
	}
	if algo == nil {
		algo = &HMACAlgorithm{DigestMethod: digest}
	}
	return &Signer{
		SecretKey:     secret,
		Salt:          salt,
		Sep:           sep,
		KeyDerivation: derivation,
		DigestMethod:  digest,
		Algorithm:     algo,
	}
}

type TimestampSigner struct {
	Signer
}

// Signs the given string.
func (s *TimestampSigner) Sign(value string) string {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, getTimestamp())
	if err != nil {
		log.Fatal(err)
	}
	ts := base64Encode(string(buf.Bytes()))
	val := value + s.Sep + ts
	return val + s.Sep + s.GetSignature(val)
}

// Unsigns the given string.
func (s *TimestampSigner) Unsign(value string, maxAge uint32) (string, error) {
	var timestamp uint32

	result, err := s.Signer.Unsign(value)
	if err != nil {
		return "", err
	}
	// If there is no timestamp in the result there is something
	// seriously wrong.
	if !strings.Contains(result, s.Sep) {
		return "", errors.New("Timestamp missing")
	}

	li := strings.LastIndex(result, s.Sep)
	val, ts := result[:li], result[li+len(s.Sep):]

	buf := bytes.NewReader([]byte(base64Decode(ts)))
	err = binary.Read(buf, binary.BigEndian, &timestamp)

	if err != nil {
		log.Fatal(err)
	}

	if maxAge > 0 {
		age := getTimestamp() - timestamp
		if age > maxAge {
			return "", errors.New(fmt.Sprintf("Signature age %d > %d seconds", age, maxAge))
		}
	}

	return val, nil
}

func NewTimestampSigner(secret, salt, sep, derivation string, digest hash.Hash, algo SigningAlgorithm) *TimestampSigner {
	signer := NewSigner(secret, salt, sep, derivation, digest, algo)
	return &TimestampSigner{Signer: *signer}
}
