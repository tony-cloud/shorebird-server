package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/shorebird-server/internal/auth"
)

type contextKey string

const (
	// ClaimsKey is the context key for auth claims.
	ClaimsKey contextKey = "auth_claims"
)

// AuthMiddleware validates JWT tokens and injects claims into the request context.
func AuthMiddleware(authService *auth.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"message":"Missing Authorization header"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				http.Error(w, `{"message":"Invalid Authorization header format"}`, http.StatusUnauthorized)
				return
			}

			token := parts[1]
			// Strip sb_api_ prefix (self-hosted API key format for Shorebird CLI compatibility)
			token = strings.TrimPrefix(token, "sb_api_")

			claims, err := authService.ValidateToken(token)
			if err != nil {
				http.Error(w, `{"message":"Invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims extracts auth claims from the request context.
func GetClaims(r *http.Request) *auth.Claims {
	claims, ok := r.Context().Value(ClaimsKey).(*auth.Claims)
	if !ok {
		return nil
	}
	return claims
}
