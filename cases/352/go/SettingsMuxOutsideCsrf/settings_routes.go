package settingscsrf

import "net/http"

func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	apiMux.HandleFunc("/settings/email", handler.UpdateEmail)
}
