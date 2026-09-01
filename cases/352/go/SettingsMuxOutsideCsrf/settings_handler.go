package settingscsrf

import "net/http"

type SettingsHandler struct {
	Service *SettingsService
}

func (h *SettingsHandler) Profile(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (h *SettingsHandler) UpdateEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	h.Service.QueueEmailChange(r.Context(), email)
	w.WriteHeader(http.StatusAccepted)
}
