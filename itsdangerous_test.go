package itsdangerous

import "testing"

func assert(t *testing.T, actual, expected string) {
	if actual != expected {
		t.Errorf("expecting %s, got %s instead", expected, actual)
	}
}

func TestSignerSign(t *testing.T) {
	s := NewSigner("secret-key", "", "", "", nil, nil)
	expected := "my string.wh6tMHxLgJqB6oY1uT73iMlyrOA"
	actual, _ := s.Sign("my string")
	assert(t, actual, expected)
}

func TestSignerUnsign(t *testing.T) {
	s := NewSigner("secret-key", "", "", "", nil, nil)
	expected := "my string"
	actual, _ := s.Unsign("my string.wh6tMHxLgJqB6oY1uT73iMlyrOA")
	assert(t, actual, expected)
}

func TestTimestampSignerUnsign(t *testing.T) {
	signer := NewTimestampSigner("secret-key", "", "", "", nil, nil)
	expected := "my string"
	actual, _ := signer.Unsign("my string.BpSAPw.NnKk1nQ206g1c1aJAS1Nxkt4aug", 0)
	assert(t, actual, expected)
}
