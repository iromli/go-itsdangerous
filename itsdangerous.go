/*
Package itsdangerous implements various functions to deal with untrusted sources.
Mainly useful for web applications.

This package exists purely as a port of https://github.com/mitsuhiko/itsdangerous,
where the original version is written in Python.
*/
package itsdangerous

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// 2011/01/01 in UTC
const EPOCH = 1293840000

// Encodes a single string. The resulting string is safe for putting into URLs.
func base64Encode(src []byte) string {
	s := base64.URLEncoding.EncodeToString(src)
	return strings.Trim(s, "=")
}

// Decodes a single string.
func base64Decode(s string) ([]byte, error) {
	var padLen int

	if l := len(s) % 4; l > 0 {
		padLen = 4 - l
	} else {
		padLen = 1
	}

	b, err := base64.URLEncoding.DecodeString(s + strings.Repeat("=", padLen))
	if err != nil {
		fmt.Println(s)
		return []byte(""), err
	}
	return b, nil
}

// Returns the current timestamp.  This implementation returns the
// seconds since 1/1/2011.
func getTimestamp() uint32 {
	return uint32(time.Now().Unix() - EPOCH)
}
