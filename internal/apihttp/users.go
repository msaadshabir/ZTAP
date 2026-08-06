package apihttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"ztap/internal/audit"
	"ztap/internal/auth"
)

type userCreateRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type userUpdateRequest struct {
	Role    *string `json:"role,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
}

type userPasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type userInfo struct {
	Username  string    `json:"username"`
	Role      auth.Role `json:"role"`
	Enabled   bool      `json:"enabled"`
	CreatedAt string    `json:"created_at"`
	LastLogin string    `json:"last_login,omitempty"`
}

func (s *Server) handleUsersRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/users" {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if s.auth == nil {
		writeError(w, http.StatusInternalServerError, errors.New("auth manager not configured"))
		return
	}

	switch r.Method {
	case http.MethodGet:
		users := s.auth.ListUsers()
		resp := make([]userInfo, 0, len(users))
		for _, user := range users {
			info := userInfo{
				Username:  user.Username,
				Role:      user.Role,
				Enabled:   user.Enabled,
				CreatedAt: user.CreatedAt.UTC().Format(timeFormat),
			}
			if !user.LastLogin.IsZero() {
				info.LastLogin = user.LastLogin.UTC().Format(timeFormat)
			}
			resp = append(resp, info)
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": resp})
	case http.MethodPost:
		var req userCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
			return
		}
		username := strings.TrimSpace(req.Username)
		password := req.Password
		role := strings.TrimSpace(req.Role)
		if username == "" || password == "" {
			writeError(w, http.StatusBadRequest, errors.New("username and password are required"))
			return
		}
		if len(password) < 8 {
			writeError(w, http.StatusBadRequest, errors.New("password must be at least 8 characters"))
			return
		}
		if role == "" {
			role = string(auth.RoleOperator)
		}
		if err := s.auth.CreateUser(username, password, auth.Role(role)); err != nil {
			if errors.Is(err, auth.ErrUserExists) {
				writeError(w, http.StatusConflict, err)
				return
			}
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if s.audit != nil {
			actor := "system"
			if sess, ok := sessionFromContext(r.Context()); ok {
				actor = sess.Username
			}
			_ = s.audit.Log(audit.EventUserCreated, actor, username, "create", map[string]any{"role": role})
		}
		user, _ := s.auth.GetUser(username)
		info := userInfo{
			Username:  user.Username,
			Role:      user.Role,
			Enabled:   user.Enabled,
			CreatedAt: user.CreatedAt.UTC().Format(timeFormat),
		}
		writeJSON(w, http.StatusCreated, info)
	default:
		writeMethodNotAllowed(w)
	}
}

func (s *Server) handleUsersRoutes(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/v1/users/") {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if s.auth == nil {
		writeError(w, http.StatusInternalServerError, errors.New("auth manager not configured"))
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/users/"), "/")
	if len(parts) < 1 {
		writeError(w, http.StatusNotFound, errors.New("invalid user path"))
		return
	}
	username := strings.TrimSpace(parts[0])
	if username == "" {
		writeError(w, http.StatusBadRequest, errors.New("username is required"))
		return
	}

	// /v1/users/{username}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			user, err := s.auth.GetUser(username)
			if err != nil {
				if errors.Is(err, auth.ErrUserNotFound) {
					writeError(w, http.StatusNotFound, err)
					return
				}
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			info := userInfo{
				Username:  user.Username,
				Role:      user.Role,
				Enabled:   user.Enabled,
				CreatedAt: user.CreatedAt.UTC().Format(timeFormat),
			}
			if !user.LastLogin.IsZero() {
				info.LastLogin = user.LastLogin.UTC().Format(timeFormat)
			}
			writeJSON(w, http.StatusOK, info)
		case http.MethodPatch:
			var req userUpdateRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
				return
			}
			if req.Role == nil && req.Enabled == nil {
				writeError(w, http.StatusBadRequest, errors.New("role or enabled must be provided"))
				return
			}
			actor := "system"
			if sess, ok := sessionFromContext(r.Context()); ok {
				actor = sess.Username
			}
			if req.Role != nil {
				if err := s.auth.SetUserRole(username, auth.Role(strings.TrimSpace(*req.Role))); err != nil {
					s.handleUserError(w, err)
					return
				}
			}
			if req.Enabled != nil {
				if *req.Enabled {
					if err := s.auth.EnableUser(username); err != nil {
						s.handleUserError(w, err)
						return
					}
					if s.audit != nil {
						_ = s.audit.Log(audit.EventUserEnabled, actor, username, "enable", nil)
					}
				} else {
					if err := s.auth.DisableUser(username); err != nil {
						s.handleUserError(w, err)
						return
					}
					if s.audit != nil {
						_ = s.audit.Log(audit.EventUserDisabled, actor, username, "disable", nil)
					}
				}
			}
			user, err := s.auth.GetUser(username)
			if err != nil {
				s.handleUserError(w, err)
				return
			}
			info := userInfo{
				Username:  user.Username,
				Role:      user.Role,
				Enabled:   user.Enabled,
				CreatedAt: user.CreatedAt.UTC().Format(timeFormat),
			}
			if !user.LastLogin.IsZero() {
				info.LastLogin = user.LastLogin.UTC().Format(timeFormat)
			}
			writeJSON(w, http.StatusOK, info)
		case http.MethodDelete:
			actor := "system"
			if sess, ok := sessionFromContext(r.Context()); ok {
				actor = sess.Username
			}
			if err := s.auth.DeleteUser(username); err != nil {
				s.handleUserError(w, err)
				return
			}
			if s.audit != nil {
				_ = s.audit.Log(audit.EventUserDisabled, actor, username, "delete", nil)
			}
			writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
		default:
			writeMethodNotAllowed(w)
		}
		return
	}

	// /v1/users/{username}/password
	if len(parts) == 2 && parts[1] == "password" {
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w)
			return
		}
		var req userPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
			return
		}
		if strings.TrimSpace(req.NewPassword) == "" {
			writeError(w, http.StatusBadRequest, errors.New("new_password is required"))
			return
		}
		if len(req.NewPassword) < 8 {
			writeError(w, http.StatusBadRequest, errors.New("password must be at least 8 characters"))
			return
		}
		if strings.TrimSpace(req.OldPassword) != "" {
			if err := s.auth.ChangePassword(username, req.OldPassword, req.NewPassword); err != nil {
				s.handleUserError(w, err)
				return
			}
		} else {
			if err := s.auth.SetPassword(username, req.NewPassword); err != nil {
				s.handleUserError(w, err)
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"updated": true})
		return
	}

	writeError(w, http.StatusNotFound, errors.New("not found"))
}

func (s *Server) handleUserError(w http.ResponseWriter, err error) {
	if err == nil {
		writeError(w, http.StatusInternalServerError, errors.New("unknown error"))
		return
	}
	if errors.Is(err, auth.ErrUserNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if errors.Is(err, auth.ErrLastAdmin) {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeError(w, http.StatusBadRequest, err)
}
