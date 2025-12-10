package hash

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

var ErrFailedToHashPassword = errors.New("failed to hash password")

type HashService struct {
	cost int
}

func NewHashService() *HashService {
	return &HashService{
		cost: bcrypt.DefaultCost,
	}
}

func (hs *HashService) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), hs.cost)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrFailedToHashPassword, err)
	}
	return string(hash), nil
}

func (hs *HashService) CheckPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
