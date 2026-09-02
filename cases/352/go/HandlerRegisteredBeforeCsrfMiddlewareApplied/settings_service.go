package main

import (
	"encoding/json"
	"net/http"
)

// AccountSettings holds the mutable, per-account preferences exposed
// through the /settings endpoint.
type AccountSettings struct {
	NotificationEmail string `json:"notification_email"`
	TwoFactorEnabled  bool   `json:"two_factor_enabled"`
}

// SettingsService owns the in-memory settings store for the current
// session's account. A real deployment would back this with a
// database keyed on the authenticated user.
type SettingsService struct {
	current AccountSettings
}

func NewSettingsService() *SettingsService {
	return &SettingsService{
		current: AccountSettings{
			NotificationEmail: "owner@example.com",
			TwoFactorEnabled:  true,
		},
	}
}

func (s *SettingsService) viewSettingsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.current)
}

// updateSettingsHandler applies a state-changing update to the
// account's settings, including turning off two-factor authentication.
// It relies entirely on whichever middleware chain the request arrived
// through to have already enforced CSRF protection.
func (s *SettingsService) updateSettingsHandler(w http.ResponseWriter, r *http.Request) {
	var update AccountSettings
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	s.current = update

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.current)
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}
