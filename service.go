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

func (s *Service) AssignPermissionToRole(ctx context.Context, role string, permissions []string) error {
	// get role id by string
	roleIDs, err := s.repo.GetRoleIDByName(ctx, []string{role})
	if err != nil {
		// Log the error or handle it as needed
		log.Printf("Error getting role ID: %v", err)
		return err
	}

	// get permission id by string
	permissionIDs, err := s.repo.GetPermissionIDByName(ctx, permissions)
	if err != nil {
		// Log the error or handle it as needed
		log.Printf("Error getting permission ID: %v", err)
		return err
	}

	// assign permission to role
	err = s.repo.GivePermissionToRole(ctx, roleIDs[0], permissionIDs)
	if err != nil {
		// Log the error or handle it as needed
		log.Printf("Error assigning permission to role: %v", err)
		return err
	}
	return nil
}
