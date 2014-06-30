package itsdangerous

import "testing"

func TestSignerSign(t *testing.T) {
	s := NewSigner("secret-key", "", "", "", nil)
	expected := "my string.wh6tMHxLgJqB6oY1uT73iMlyrOA"
	actual := s.Sign("my string")

	if actual != expected {
		t.Errorf("expecting %s, got %s instead", expected, actual)
	}
}
