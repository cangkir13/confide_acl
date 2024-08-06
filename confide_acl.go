// Copyright 2024 Cangkir14. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.
// https://github.com/cangkir13/confide_acl
// confide_acl library is for managing roles and permissions in an application.
package confide_acl

import (
	"context"
	"database/sql"

	"github.com/cangkir13/confide_acl/repository"
)

// #Table default table for user
var defaultTable string = "users"

// config acl service struct
type ConfigACL struct {
	Database     *sql.DB
	TableAccount string // setup default table if not set it's changes to defaultTable
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

// ConfideACL interface
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
func NewService(conf ConfigACL) *service {
	if conf.TableAccount == "" {
		conf.TableAccount = defaultTable
	}
	return &service{
		repo: repository.NewSQL(conf.Database, conf.TableAccount),
	}
}
