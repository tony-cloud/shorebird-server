package handlers

import (
	"net/http"

	"github.com/shorebird-server/internal/api/middleware"
	"github.com/shorebird-server/internal/auth"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	DB          *db.DB
	AuthService *auth.Service
}

// Login handles POST /auth/token
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
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
	// For simplicity, re-validate the current token and issue a new one.
	// In production, you'd maintain a refresh token table.
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

// Register handles POST /auth/register (self-hosted convenience endpoint)
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

	// Create a default organization for the user
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
