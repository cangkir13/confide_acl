package confide_acl

import (
	"context"
	"database/sql"

	"github.com/cangkir13/confide_acl/repository"
)

// table default if not set
var defaultTable string = "users"

// config acl service struct
type ConfigACL struct {
	Database     *sql.DB
	TableAccount string
}

type RepositoryService interface {
	CreateRole(ctx context.Context, name string) error
	CreatePermission(ctx context.Context, name string) error
	GetAccountPermission(ctx context.Context, userid uint, permissionid []uint) ([]repository.AccountPermission, error)
	GetAccountRole(ctx context.Context, userid uint, roleid []uint) ([]repository.AccountRole, error)
	GetPermissionIDByName(ctx context.Context, permissions []string) ([]uint, error)
	GetRoleIDByName(ctx context.Context, names []string) ([]uint, error)
	GivePermissionToRole(ctx context.Context, roleID uint, permissions []uint) error
	GiveRoleToUser(ctx context.Context, userID uint, roleID uint) error
}

type ConfideACL interface {
	AddRole(ctx context.Context, name string) error
	AddPermission(ctx context.Context, name string) error
	AssignPermissionToRole(ctx context.Context, role string, permissions []string) error
	AssignUserToRole(ctx context.Context, userid uint, role string) error
	VerifyPrivilege(ctx context.Context, userid int, rp RolePermission) (bool, error)
}

type service struct {
	repo repository.SQL
}

// NewService creates a new instance of the Service struct.
//
// Parameters:
// - conf: ConfigACL struct containing the database connection and default table account.
//
// Returns:
// - a pointer to the Service struct.
func NewService(conf ConfigACL) service {
	if conf.TableAccount == "" {
		conf.TableAccount = defaultTable
	}
	return service{
		repo: repository.NewSQL(conf.Database, conf.TableAccount),
	}
}
