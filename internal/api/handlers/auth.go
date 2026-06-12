package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shorebird-server/internal/api/middleware"
	"github.com/shorebird-server/internal/auth"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
)

// ---- OAuth auth code store ----

type authCodeStore struct {
	mu    sync.Mutex
	codes map[string]authCodeEntry
}

type authCodeEntry struct {
	email     string
	expiresAt time.Time
}

var globalCodeStore = &authCodeStore{codes: make(map[string]authCodeEntry)}

func (s *authCodeStore) set(email string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	code := generateCode()
	s.codes[code] = authCodeEntry{email: email, expiresAt: time.Now().Add(5 * time.Minute)}
	for c, e := range s.codes {
		if time.Now().After(e.expiresAt) {
			delete(s.codes, c)
		}
	}
	return code
}

func (s *authCodeStore) validate(code string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.codes[code]
	if !ok || time.Now().After(entry.expiresAt) {
		delete(s.codes, code)
		return "", false
	}
	delete(s.codes, code)
	return entry.email, true
}

func generateCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- OAuth token response ----

type oauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// ---- AuthHandler ----

type AuthHandler struct {
	DB          db.Store
	AuthService *auth.Service
}

// LoginPage handles GET /auth/login — OAuth HTML login form.
func (h *AuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	continueURL := r.URL.Query().Get("continue")
	if continueURL == "" {
		respondError(w, http.StatusBadRequest, "Missing continue parameter", nil)
		return
	}

	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")
		if email == "" || password == "" {
			serveLoginHTML(w, continueURL, "Email and password are required.")
			return
		}
		user, err := h.DB.GetUserByEmail(r.Context(), email)
		if err != nil || auth.CheckPassword(user.PasswordHash, password) != nil {
			serveLoginHTML(w, continueURL, "Invalid email or password.")
			return
		}
		code := globalCodeStore.set(user.Email)
		http.Redirect(w, r, fmt.Sprintf("%s?code=%s", continueURL, code), http.StatusFound)
		return
	}

	serveLoginHTML(w, continueURL, "")
}

// Login handles POST /auth/token — supports OAuth form-encoded + JSON body.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")

	// --- OAuth 2.0 form-encoded ---
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid form data", nil)
			return
		}
		grantType := r.FormValue("grant_type")

		switch grantType {
		case "authorization_code":
			code := r.FormValue("code")
			if code == "" {
				respondError(w, http.StatusBadRequest, "Missing code parameter", nil)
				return
			}
			email, valid := globalCodeStore.validate(code)
			if !valid {
				respondError(w, http.StatusBadRequest, "Invalid or expired authorization code", strPtr("Request a new code from /auth/login"))
				return
			}
			user, err := h.DB.GetUserByEmail(r.Context(), email)
			if err != nil {
				respondError(w, http.StatusInternalServerError, "User not found", nil)
				return
			}
			h.writeOAuthTokenResponse(w, user.ID, user.Email)

		case "refresh_token":
			refreshToken := r.FormValue("refresh_token")
			if refreshToken == "" {
				respondError(w, http.StatusBadRequest, "Missing refresh_token parameter", nil)
				return
			}
			claims, err := h.AuthService.ValidateToken(strings.TrimPrefix(refreshToken, "sb_api_"))
			if err != nil {
				respondError(w, http.StatusBadRequest, "Invalid refresh token", nil)
				return
			}
			h.writeOAuthTokenResponse(w, claims.UserID, claims.Email)

		default:
			respondError(w, http.StatusBadRequest, "Unsupported grant_type: "+grantType, nil)
		}
		return
	}

	// --- JSON body login (Web UI + direct API) ---
	var req models.AuthTokenRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	user, err := h.DB.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid email or password", nil)
		return
	}

	if err := auth.CheckPassword(user.PasswordHash, req.Password); err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid email or password", nil)
		return
	}

	token, err := h.AuthService.GenerateToken(user.ID, user.Email)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate token", nil)
		return
	}

	refreshToken, err := auth.GenerateRefreshToken()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate refresh token", nil)
		return
	}

	respondJSON(w, http.StatusOK, models.AuthTokenResponse{
		Token:        token,
		RefreshToken: refreshToken,
		Email:        user.Email,
	})
}

// Refresh handles POST /auth/refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Invalid token", nil)
		return
	}

	token, err := h.AuthService.GenerateToken(claims.UserID, claims.Email)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate token", nil)
		return
	}

	refreshToken, err := auth.GenerateRefreshToken()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate refresh token", nil)
		return
	}

	respondJSON(w, http.StatusOK, models.AuthTokenResponse{
		Token:        token,
		RefreshToken: refreshToken,
		Email:        claims.Email,
	})
}

// Register handles POST /auth/register
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	passwordHash, err := auth.HashPassword(req.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to hash password", nil)
		return
	}

	userID, err := h.DB.CreateUser(r.Context(), req.Email, req.Name, passwordHash)
	if err != nil {
		respondError(w, http.StatusConflict, "User already exists", strPtr(err.Error()))
		return
	}

	orgID, err := h.DB.CreateOrganization(r.Context(), req.Name+"'s Org", "team")
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create organization", nil)
		return
	}

	if err := h.DB.AddUserToOrganization(r.Context(), userID, orgID, "admin"); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to add user to organization", nil)
		return
	}

	token, err := h.AuthService.GenerateToken(userID, req.Email)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate token", nil)
		return
	}

	respondJSON(w, http.StatusCreated, models.AuthTokenResponse{
		Token: token,
		Email: req.Email,
	})
}

func (h *AuthHandler) writeOAuthTokenResponse(w http.ResponseWriter, userID int, email string) {
	jwt, _ := h.AuthService.GenerateToken(userID, email)
	refresh, _ := auth.GenerateRefreshToken()
	respondJSON(w, http.StatusOK, oauthTokenResponse{
		AccessToken:  jwt,
		RefreshToken: "sb_rt_" + refresh,
		TokenType:    "Bearer",
		ExpiresIn:    900,
	})
}

// ---- HTML login page ----

func serveLoginHTML(w http.ResponseWriter, continueURL, errorMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errorHTML := ""
	if errorMsg != "" {
		errorHTML = fmt.Sprintf(`<div class="error">%s</div>`, errorMsg)
	}
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shorebird Login</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{background:#fff;border-radius:12px;box-shadow:0 4px 6px rgba(0,0,0,.07),0 2px 4px rgba(0,0,0,.06);padding:40px;width:100%%;max-width:400px}
  .card h1{font-size:24px;font-weight:700;text-align:center;margin-bottom:4px}
  .card .st{color:#64748b;text-align:center;font-size:14px;margin-bottom:24px}
  .fg{margin-bottom:16px}
  .fg label{display:block;font-size:13px;font-weight:600;color:#64748b;margin-bottom:5px}
  .fg input{width:100%%;padding:10px 14px;border:1px solid #e2e8f0;border-radius:8px;font-size:14px;outline:none;transition:border-color .15s}
  .fg input:focus{border-color:#0891b2;box-shadow:0 0 0 3px rgba(8,145,178,.1)}
  .btn{width:100%%;padding:12px;background:#0891b2;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer}
  .btn:hover{background:#0e7490}
  .error{background:#fef2f2;color:#ef4444;padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:13px}
</style>
</head>
<body>
<div class="card">
  <h1>🐦 Shorebird</h1>
  <p class="st">Self-Hosted · Sign in to continue</p>
  %s
  <form method="POST" action="">
    <div class="fg"><label for="email">Email</label><input type="email" id="email" name="email" placeholder="you@example.com" required autofocus></div>
    <div class="fg"><label for="password">Password</label><input type="password" id="password" name="password" placeholder="Enter password" required></div>
    <button type="submit" class="btn">Sign In</button>
  </form>
</div>
</body>
</html>`, errorHTML)
}
