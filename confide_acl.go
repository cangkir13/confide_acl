package confide_acl

import (
	"context"
	"database/sql"

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

type ConfideACL interface {
	SetRole(ctx context.Context, name string) error
	SetPermission(ctx context.Context, name string) error
	AssignPermissionToRole(ctx context.Context, role string, permissions []string) error
	ValidateControl(ctx context.Context, args string) (bool, error)
}
