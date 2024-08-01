package confideacl

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cangkir13/confide_acl/repository"
	"github.com/stretchr/testify/require"
)

func TestCreateRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	_ = repository.NewSQL(db)
	service := NewService(db)

	// Periksa format dan ekspektasi query
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO roles (name) VALUES (?)")).
		WithArgs("admin").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = service.CreateRole(context.Background(), "admin")
	require.NoError(t, err)
	err = mock.ExpectationsWereMet()
	require.NoError(t, err)
}

func TestCreatePermission(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	_ = repository.NewSQL(db)
	service := NewService(db)

	// Periksa format dan ekspektasi query
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO permissions (name) VALUES (?)")).
		WithArgs("read").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = service.CreatePermission(context.Background(), "read")
	require.NoError(t, err)
	err = mock.ExpectationsWereMet()
	require.NoError(t, err)
}

func TestAssignPermissionToRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewService(db)

	// Define test values
	roleName := "admin"
	permissions := []string{"read", "write"}

	// Define expected role ID and permission IDs
	expectedRoleID := uint(1)
	expectedPermissionIDs := []uint{1, 2}

	// Define mock rows for role ID
	roleRows := sqlmock.NewRows([]string{"id"}).AddRow(expectedRoleID)

	// Define mock rows for permission IDs
	permissionRows := sqlmock.NewRows([]string{"id"}).
		AddRow(expectedPermissionIDs[0]).
		AddRow(expectedPermissionIDs[1])

	// Set up expectations

	// Expect GetRoleIDByName to be called and return the role ID
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM roles WHERE name IN (?)")).
		WithArgs(roleName).
		WillReturnRows(roleRows)

	// Expect GetPermissionIDByName to be called and return permission IDs
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM permissions WHERE name IN (?,?)")).
		WithArgs(permissions[0], permissions[1]).
		WillReturnRows(permissionRows)

	// Expect transaction to start
	mock.ExpectBegin()
	// Expect GivePermissionToRole to be called for each permission ID
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO role_has_permissions (role_id, permission_id) VALUES (?, ?)")).
		WithArgs(expectedRoleID, expectedPermissionIDs[0]).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO role_has_permissions (role_id, permission_id) VALUES (?, ?)")).
		WithArgs(expectedRoleID, expectedPermissionIDs[1]).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Expect transaction to commit
	mock.ExpectCommit()

	// Call the service method
	err = service.AssignPermissionToRole(context.Background(), roleName, permissions)
	require.NoError(t, err)

	// Ensure all expectations were met
	err = mock.ExpectationsWereMet()
	require.NoError(t, err)
}
