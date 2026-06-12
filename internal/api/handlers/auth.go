package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/shorebird-server/internal/api/middleware"
	"github.com/shorebird-server/internal/auth"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/email"
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
	Mailer      *email.Mailer
	BaseURL     string
}

type casdoorProfile struct {
	Email string
	Name  string
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
			serveLoginHTML(w, continueURL, "Email and password are required.", h.ssoEnabled(r))
			return
		}
		user, err := h.DB.GetUserByEmail(r.Context(), email)
		if err != nil || auth.CheckPassword(user.PasswordHash, password) != nil {
			serveLoginHTML(w, continueURL, "Invalid email or password.", h.ssoEnabled(r))
			return
		}
		if !user.EmailVerified {
			serveLoginHTML(w, continueURL, "Verify your email address before signing in.", h.ssoEnabled(r))
			return
		}
		code := globalCodeStore.set(user.Email)
		http.Redirect(w, r, fmt.Sprintf("%s?code=%s", continueURL, code), http.StatusFound)
		return
	}

	serveLoginHTML(w, continueURL, "", h.ssoEnabled(r))
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
			if !user.EmailVerified {
				respondError(w, http.StatusForbidden, "Email verification required", strPtr("Verify your email address before signing in."))
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
			user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
			if err != nil || !user.EmailVerified {
				respondError(w, http.StatusForbidden, "Email verification required", nil)
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
	if !user.EmailVerified {
		respondError(w, http.StatusForbidden, "Email verification required", strPtr("Verify your email address before signing in."))
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
		Token:              token,
		RefreshToken:       refreshToken,
		Email:              user.Email,
		MustChangePassword: user.MustChangePassword,
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
	if !h.boolSetting(r, "registration_enabled", true) {
		respondError(w, http.StatusForbidden, "Registration is disabled", nil)
		return
	}
	if h.boolSetting(r, "sso_only_registration", false) {
		respondError(w, http.StatusForbidden, "Password registration is disabled", strPtr("Use SSO to create an account."))
		return
	}
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

	if err := h.sendVerificationEmail(r, userID, req.Email); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to send verification email", strPtr(err.Error()))
		return
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"email":   req.Email,
		"message": "Account created. Check your email to verify the account before signing in.",
	})
}

func (h *AuthHandler) PublicSettings(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"registration_enabled":     h.boolSetting(r, "registration_enabled", true),
		"sso_registration_enabled": h.boolSetting(r, "sso_registration_enabled", true),
		"sso_only_registration":    h.boolSetting(r, "sso_only_registration", false),
		"sso_enabled":              h.ssoEnabled(r),
	})
}

func (h *AuthHandler) RequestVerificationEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}
	user, err := h.DB.GetUserByEmail(r.Context(), req.Email)
	if err == nil && !user.EmailVerified {
		_ = h.sendVerificationEmail(r, user.ID, user.Email)
	}
	respondJSON(w, http.StatusOK, map[string]string{"message": "If the account exists, a verification email has been sent."})
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		respondError(w, http.StatusBadRequest, "Missing token", nil)
		return
	}
	row, err := h.DB.ConsumeAccountToken(r.Context(), hashToken(token), "email_verification")
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid or expired verification token", nil)
		return
	}
	if err := h.DB.MarkUserEmailVerified(r.Context(), row.UserID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to verify email", nil)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<html><body><p>Email verified. You can close this page and sign in.</p></body></html>`)
}

func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}
	if user, err := h.DB.GetUserByEmail(r.Context(), req.Email); err == nil {
		token := generateURLToken()
		if err := h.DB.CreateAccountToken(r.Context(), user.ID, hashToken(token), "password_reset", time.Now().Add(time.Hour)); err == nil {
			resetURL := fmt.Sprintf("%s/auth/password-reset?token=%s", h.publicBaseURL(r), url.QueryEscape(token))
			_ = h.Mailer.Send(user.Email, "Reset your Shorebird password", "Use this link to reset your password:\n\n"+resetURL+"\n\nThis link expires in 1 hour.")
		}
	}
	respondJSON(w, http.StatusOK, map[string]string{"message": "If the account exists, a password reset email has been sent."})
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}
	row, err := h.DB.ConsumeAccountToken(r.Context(), hashToken(req.Token), "password_reset")
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid or expired reset token", nil)
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to hash password", nil)
		return
	}
	if err := h.DB.UpdateUserPassword(r.Context(), row.UserID, hash); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update password", nil)
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"message": "Password updated"})
}

func (h *AuthHandler) PasswordResetPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Reset Password</title>
<style>*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:white;border:1px solid #e2e8f0;border-radius:8px;padding:32px;width:100%%;max-width:420px}label{display:block;font-size:13px;font-weight:600;color:#64748b;margin:14px 0 5px}input{width:100%%;padding:10px;border:1px solid #e2e8f0;border-radius:8px}button{margin-top:18px;width:100%%;padding:12px;border:0;border-radius:8px;background:#0891b2;color:white;font-weight:600}.msg{font-size:14px;margin-top:14px}</style></head>
<body><div class="card"><h2>Reset Password</h2><form id="f"><input type="hidden" id="token" value="%s"><label for="password">New password</label><input type="password" id="password" minlength="6" required><button type="submit">Update password</button><div class="msg" id="msg"></div></form></div>
<script>document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();const res=await fetch('/auth/password-reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:document.getElementById('token').value,password:document.getElementById('password').value})});const data=await res.json().catch(()=>({message:'Password updated'}));document.getElementById('msg').textContent=res.ok?'Password updated. You can sign in now.':(data.message||'Failed to update password');});</script></body></html>`, token)
}

func (h *AuthHandler) SSOLogin(w http.ResponseWriter, r *http.Request) {
	settings, _ := h.DB.ListSettings(r.Context())
	endpoint := strings.TrimRight(settings["casdoor_endpoint"], "/")
	clientID := settings["casdoor_client_id"]
	if endpoint == "" || clientID == "" {
		respondError(w, http.StatusBadRequest, "SSO is not configured", nil)
		return
	}
	continueURL := r.URL.Query().Get("continue")
	mode := r.URL.Query().Get("mode")
	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("response_type", "code")
	values.Set("scope", "openid profile email")
	values.Set("redirect_uri", h.publicBaseURL(r)+"/auth/sso/callback")
	if settings["casdoor_organization"] != "" {
		values.Set("organization", settings["casdoor_organization"])
	}
	state := base64.RawURLEncoding.EncodeToString([]byte(url.Values{"continue": {continueURL}, "mode": {mode}}.Encode()))
	values.Set("state", state)
	http.Redirect(w, r, endpoint+"/login/oauth/authorize?"+values.Encode(), http.StatusFound)
}

func (h *AuthHandler) SSOCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		respondError(w, http.StatusBadRequest, "Missing SSO code", nil)
		return
	}
	stateValues := url.Values{}
	if raw := r.URL.Query().Get("state"); raw != "" {
		if decoded, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
			stateValues, _ = url.ParseQuery(string(decoded))
		}
	}
	profile, err := h.exchangeCasdoorProfile(r, code)
	if err != nil {
		respondError(w, http.StatusBadGateway, "SSO login failed", strPtr(err.Error()))
		return
	}
	user, err := h.DB.GetUserByEmail(r.Context(), profile.Email)
	if err != nil {
		if !h.boolSetting(r, "sso_registration_enabled", true) {
			respondError(w, http.StatusForbidden, "SSO registration is disabled", nil)
			return
		}
		passwordHash, _ := auth.HashPassword(generateURLToken())
		userID, err := h.DB.CreateUser(r.Context(), profile.Email, profile.Name, passwordHash)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to create SSO user", strPtr(err.Error()))
			return
		}
		_ = h.DB.MarkUserEmailVerified(r.Context(), userID)
		orgID, err := h.DB.CreateOrganization(r.Context(), profile.Name+"'s Org", "team")
		if err == nil {
			_ = h.DB.AddUserToOrganization(r.Context(), userID, orgID, "admin")
		}
		user, _ = h.DB.GetUserByID(r.Context(), userID)
	}
	if user == nil || !user.EmailVerified {
		respondError(w, http.StatusForbidden, "Email verification required", nil)
		return
	}
	if stateValues.Get("continue") != "" {
		code := globalCodeStore.set(user.Email)
		http.Redirect(w, r, fmt.Sprintf("%s?code=%s", stateValues.Get("continue"), code), http.StatusFound)
		return
	}
	token, _ := h.AuthService.GenerateToken(user.ID, user.Email)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<html><body><script>localStorage.setItem('shorebird_token', %q); location.href='/';</script></body></html>`, token)
}

func (h *AuthHandler) sendVerificationEmail(r *http.Request, userID int, userEmail string) error {
	token := generateURLToken()
	if err := h.DB.CreateAccountToken(r.Context(), userID, hashToken(token), "email_verification", time.Now().Add(24*time.Hour)); err != nil {
		return err
	}
	verifyURL := fmt.Sprintf("%s/auth/verify-email?token=%s", h.publicBaseURL(r), url.QueryEscape(token))
	return h.Mailer.Send(userEmail, "Verify your Shorebird account", "Use this link to verify your account:\n\n"+verifyURL+"\n\nThis link expires in 24 hours.")
}

func (h *AuthHandler) boolSetting(r *http.Request, key string, defaultValue bool) bool {
	value, err := h.DB.GetSetting(r.Context(), key)
	if err != nil {
		return defaultValue
	}
	return strings.EqualFold(value, "true") || value == "1" || strings.EqualFold(value, "yes")
}

func (h *AuthHandler) ssoEnabled(r *http.Request) bool {
	settings, err := h.DB.ListSettings(r.Context())
	if err != nil {
		return false
	}
	return settings["casdoor_endpoint"] != "" && settings["casdoor_client_id"] != ""
}

func (h *AuthHandler) publicBaseURL(r *http.Request) string {
	if h.BaseURL != "" {
		return strings.TrimRight(h.BaseURL, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func generateURLToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (h *AuthHandler) exchangeCasdoorProfile(r *http.Request, code string) (*casdoorProfile, error) {
	settings, _ := h.DB.ListSettings(r.Context())
	endpoint := strings.TrimRight(settings["casdoor_endpoint"], "/")
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", settings["casdoor_client_id"])
	form.Set("client_secret", settings["casdoor_client_secret"])
	form.Set("code", code)
	form.Set("redirect_uri", h.publicBaseURL(r)+"/auth/sso/callback")
	resp, err := http.PostForm(endpoint+"/api/login/oauth/access_token", form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", strings.TrimSpace(string(body)))
	}
	var tokenResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return nil, fmt.Errorf("SSO token response missing access_token")
	}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint+"/api/get-account", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	acctResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer acctResp.Body.Close()
	var account map[string]interface{}
	if err := json.NewDecoder(acctResp.Body).Decode(&account); err != nil {
		return nil, err
	}
	data, _ := account["data"].(map[string]interface{})
	if data == nil {
		data = account
	}
	profile := &casdoorProfile{}
	profile.Email, _ = data["email"].(string)
	profile.Name, _ = data["displayName"].(string)
	if profile.Name == "" {
		profile.Name, _ = data["name"].(string)
	}
	if profile.Name == "" {
		profile.Name = profile.Email
	}
	if profile.Email == "" {
		return nil, fmt.Errorf("SSO profile missing email")
	}
	return profile, nil
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

func serveLoginHTML(w http.ResponseWriter, continueURL, errorMsg string, ssoEnabled bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errorHTML := ""
	if errorMsg != "" {
		errorHTML = fmt.Sprintf(`<div class="error">%s</div>`, errorMsg)
	}
	ssoHTML := ""
	if ssoEnabled {
		ssoHTML = fmt.Sprintf(`<a class="btn secondary" href="/auth/sso/login?continue=%s">Sign in with Casdoor</a>`, url.QueryEscape(continueURL))
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
  .btn.secondary{display:block;text-align:center;text-decoration:none;margin-top:12px;background:#111827}
  .btn.secondary:hover{background:#1f2937}
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
  %s
</div>
</body>
</html>`, errorHTML, ssoHTML)
}
