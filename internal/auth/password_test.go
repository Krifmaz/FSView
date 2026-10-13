package auth

import (
	"strings"
	"testing"
)

func TestHashVerify(t *testing.T) {
	h, err := hashWith("correct horse", Params{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=1024,t=1,p=1$") {
		t.Fatalf("format: %s", h)
	}
	if ok, err := VerifyPassword("correct horse", h); !ok || err != nil {
		t.Fatal("valid password rejected")
	}
	if ok, _ := VerifyPassword("wrong", h); ok {
		t.Fatal("wrong password accepted")
	}
	if _, err := VerifyPassword("x", "$2y$10$bcrypt"); err == nil {
		t.Fatal("non-argon hash accepted")
	}
	p, _ := GeneratePassword(20)
	if len(p) != 20 {
		t.Fatal("length")
	}
}
