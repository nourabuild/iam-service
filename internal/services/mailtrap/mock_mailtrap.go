package mailtrap

import "context"

type mockMailtrapService struct{}

func NewMockMailtrapService() MailtrapRepository {
	return &mockMailtrapService{}
}

func (m *mockMailtrapService) SendPasswordResetEmail(_ context.Context, _, _ string) error {
	return nil
}
