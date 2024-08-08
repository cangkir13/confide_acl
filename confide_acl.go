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

// ConfideACL interface
type ConfideACL interface {
	AddRole(ctx context.Context, name string) error
	AddPermission(ctx context.Context, name string) error
	AssignPermissionToRole(ctx context.Context, role string, permissions []string) error
	AssignUserToRole(ctx context.Context, userid uint, role string) error
	PolicyACL(ctx context.Context, userid int, rolePermission, module, method string) (bool, error)
}

// NewService creates a new instance of the Service struct.
//
// Parameters:
// - conf: ConfigACL struct containing the database connection and default table account.
//
// Returns:
// - a pointer to the Service struct.
func NewService(conf ConfigACL) ConfideACL {
	if conf.TableAccount == "" {
		conf.TableAccount = defaultTable
	}
	return &service{
		repo: repository.NewSQL(conf.Database, conf.TableAccount),
	}
}
