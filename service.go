package confideacl

import (
	"context"
	"database/sql"
	"log"

	"github.com/cangkir13/confide_acl/repository"
)

type Service struct {
	repo *repository.SQL
}

func NewService(db *sql.DB) *Service {
	return &Service{
		repo: repository.NewSQL(db),
	}
}

func (s *Service) CreateRole(ctx context.Context, name string) error {
	err := s.repo.CreateRole(ctx, name)
	if err != nil {
		// Log the error or handle it as needed
		log.Printf("Error creating role: %v", err)
		return err
	}
	return nil
}

func (s *Service) CreatePermission(ctx context.Context, name string) error {
	err := s.repo.CreatePermission(ctx, name)
	if err != nil {
		// Log the error or handle it as needed
		log.Printf("Error creating permission: %v", err)
		return err
	}
	return nil
}
