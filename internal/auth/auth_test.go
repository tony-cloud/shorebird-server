package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestValidateTokenAcceptsServerIssuedToken(t *testing.T) {
	service := NewService("test-secret", time.Hour)
	// A 254-byte email also appears in the subject claim.
	email := strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 56) + ".test"
	token, err := service.GenerateToken(42, email)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) >= 1024 {
		t.Fatalf("server-issued token length = %d, expected under 1 KiB", len(token))
	}
	claims, err := service.ValidateToken(token)
	if err != nil || claims == nil || claims.UserID != 42 || claims.Email != email {
		t.Fatalf("server-issued token rejected: claims = %v, err = %v", claims, err)
	}
}

func TestValidateTokenBoundsSignedInput(t *testing.T) {
	service := NewService("test-secret", time.Hour)
	for _, padding := range []int{MaxTokenLength / 2, MaxTokenLength} {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
			RegisteredClaims: jwt.RegisteredClaims{Issuer: "shorebird-auth", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
			UserID:           42,
			Email:            "user@example.test",
			Aud:              "shorebird",
		})
		token.Header["padding"] = strings.Repeat("a", padding)
		signed, err := token.SignedString([]byte("test-secret"))
		if err != nil {
			t.Fatal(err)
		}
		claims, err := service.ValidateToken(signed)
		if len(signed) <= MaxTokenLength {
			if err != nil || claims == nil || claims.UserID != 42 {
				t.Fatalf("valid %d-byte JWT rejected: %v", len(signed), err)
			}
		} else if !errors.Is(err, jwt.ErrTokenMalformed) || claims != nil {
			t.Fatalf("oversized signed JWT accepted: claims = %v, err = %v", claims, err)
		}
	}
}

func TestValidateTokenRejectsOversizedInputBeforeParsing(t *testing.T) {
	service := NewService("test-secret", time.Hour)
	for _, size := range []int{MaxTokenLength + 1, 64 * 1024} {
		// Construct the attack string once; rejection itself must not allocate
		// parser state or a slice for the many dot-separated segments.
		malformed := strings.Repeat(".", size)
		allocations := testing.AllocsPerRun(20, func() {
			claims, err := service.ValidateToken(malformed)
			if claims != nil || !errors.Is(err, jwt.ErrTokenMalformed) {
				t.Fatalf("oversized JWT: claims = %v, err = %v", claims, err)
			}
		})
		if allocations != 0 {
			t.Fatalf("rejecting %d bytes allocated %g times, want zero", size, allocations)
		}
	}
}
