package settingscsrf

import "context"

type SettingsService struct{}

func (s *SettingsService) QueueEmailChange(ctx context.Context, email string) {
}
