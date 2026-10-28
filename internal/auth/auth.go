package auth

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Service handles JWT token creation and validation.
type Service struct {
	jwtSecret     []byte
	tokenDuration time.Duration
}

// Claims represents the JWT claims.
type Claims struct {
	jwt.RegisteredClaims
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	Aud    string `json:"aud"`
}

// NewService creates a new auth service.
func NewService(jwtSecret string, tokenDuration time.Duration) *Service {
	return &Service{
		jwtSecret:     []byte(jwtSecret),
		tokenDuration: tokenDuration,
	}
}

// TokenDuration returns the lifetime advertised to OAuth clients.
func (s *Service) TokenDuration() time.Duration { return s.tokenDuration }

// GenerateToken creates a new JWT for the given user.
func (s *Service) GenerateToken(userID int, email string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "shorebird-auth",
			Subject:   email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.tokenDuration)),
			ID:        generateID(),
		},
		UserID: userID,
		Email:  email,
		Aud:    "shorebird",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = "shorebird-self-hosted"
	return token.SignedString(s.jwtSecret)
}

// ValidateToken parses and validates a JWT token string.
func (s *Service) ValidateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("shorebird-auth"))
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	return claims, nil
}

// GenerateRefreshToken creates a random refresh token.
func GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashPassword creates a bcrypt hash of the password.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword compares a password against its hash.
func CheckPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
