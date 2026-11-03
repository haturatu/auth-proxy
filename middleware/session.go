package middleware

import (
	"auth-proxy/models"
	"auth-proxy/types"
	"context"
	"errors"
	"net/http"
)

var (
	ErrMissingSession = errors.New("session cookie missing")
	ErrInvalidSession = errors.New("invalid or expired session")
)

// resolveSessionUser is the single source of truth for validating DB-backed
// browser sessions. Each entry point decides how to report the error.
func resolveSessionUser(r *http.Request) (*types.User, error) {
	cookie, err := r.Cookie("auth_token")
	if err != nil || cookie.Value == "" {
		return nil, ErrMissingSession
	}
	user, err := models.GetUserByToken(cookie.Value)
	if err != nil {
		return nil, err
	}
	if user == nil || !user.IsActive {
		return nil, ErrInvalidSession
	}
	return user, nil
}

func sessionUserRequest(r *http.Request, user *types.User) *http.Request {
	ctx := context.WithValue(r.Context(), types.SessionDataContextKey, user)
	return r.WithContext(ctx)
}

func expireSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: "auth_token",
		Path: "/",
		MaxAge: -1,
		HttpOnly: true,
		Secure: CookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}
