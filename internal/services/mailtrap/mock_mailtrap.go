package mailtrap

type mockMailtrapService struct{}

func NewMockMailtrapService() MailtrapRepository {
	return &mockMailtrapService{}
}

func (m *mockMailtrapService) SendPasswordResetEmail(to, token string) error {
	// mock implementation, do nothing
	return nil
}
