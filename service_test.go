package confide_acl

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var tableuser string = "users"

func TestCreateRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	conf := ConfigACL{
		Database:     db,
		TableAccount: "test",
	}
	service := NewService(conf)

	// Periksa format dan ekspektasi query
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO roles (name) VALUES (?)")).
		WithArgs("admin").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = service.AddRole(context.Background(), "admin")
	require.NoError(t, err)
	err = mock.ExpectationsWereMet()
	require.NoError(t, err)
}

func TestCreatePermission(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	conf := ConfigACL{
		Database:     db,
		TableAccount: "test",
	}
	service := NewService(conf)

	// Periksa format dan ekspektasi query
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO permissions (name) VALUES (?)")).
		WithArgs("read").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = service.AddPermission(context.Background(), "read")
	require.NoError(t, err)
	err = mock.ExpectationsWereMet()
	require.NoError(t, err)
}

func TestAssignPermissionToRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	conf := ConfigACL{
		Database:     db,
		TableAccount: "test",
	}
	service := NewService(conf)

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

func TestValidateControl(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	conf := ConfigACL{
		Database:     db,
		TableAccount: "test",
	}
	service := NewService(conf)

	tests := []struct {
		name           string
		args           string
		mockRoleIDs    []uint
		mockPermIDs    []uint
		mockFunc       func()
		expectedResult bool
		expectedError  bool
	}{
		{
			name:        "Valid roles and permissions",
			args:        "role:Admin|permission:read",
			mockRoleIDs: []uint{1},
			mockPermIDs: []uint{2},
			mockFunc: func() {
				// Mock query to get role IDs
				roleRows := sqlmock.NewRows([]string{"id"})
				for _, id := range []uint{1} {
					roleRows.AddRow(id)
				}
				mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM roles WHERE name IN (?)")).
					WithArgs("Admin").
					WillReturnRows(roleRows)

				// Mock query to get permission IDs
				permRows := sqlmock.NewRows([]string{"id"})
				for _, id := range []uint{2} {
					permRows.AddRow(id)
				}
				mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM permissions WHERE name IN (?)")).
					WithArgs("read").
					WillReturnRows(permRows)

				// Mock query to check permissions
				mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM role_has_permissions WHERE role_id IN (?) AND permission_id IN (?)")).
					WithArgs(1, 2).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
			},
			expectedResult: true,
			expectedError:  false,
		},
		{
			name: "Error getting role IDs",
			args: "role:Admin",
			mockFunc: func() {
				mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM roles WHERE name IN (?)")).
					WithArgs("Admin").
					WillReturnError(assert.AnError)
			},
			expectedResult: false,
			expectedError:  true,
		},
		{
			name: "Error getting permission IDs",
			args: "permission:read",
			mockFunc: func() {
				mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM permissions WHERE name IN (?)")).
					WithArgs("read").
					WillReturnError(assert.AnError)
			},
			expectedResult: false,
			expectedError:  true,
		},
		{
			name:        "Error checking permissions",
			args:        "role:Admin|permission:read",
			mockRoleIDs: []uint{1},
			mockPermIDs: []uint{2},
			mockFunc: func() {
				// Mock query to get role IDs
				roleRows := sqlmock.NewRows([]string{"id"})
				for _, id := range []uint{1} {
					roleRows.AddRow(id)
				}
				mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM roles WHERE name IN (?)")).
					WithArgs("Admin").
					WillReturnRows(roleRows)

				// Mock query to get permission IDs
				permRows := sqlmock.NewRows([]string{"id"})
				for _, id := range []uint{2} {
					permRows.AddRow(id)
				}
				mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM permissions WHERE name IN (?)")).
					WithArgs("read").
					WillReturnRows(permRows)

				// Mock query to check permissions
				mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM role_has_permissions WHERE role_id IN (?) AND permission_id IN (?)")).
					WithArgs(1, 2).
					WillReturnError(assert.AnError)
			},
			expectedResult: false,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock expectations using mockFunc
			if tt.mockFunc != nil {
				tt.mockFunc()
			}

			// Call the service method
			ctx := context.Background()
			result, err := service.ValidateControl(ctx, tt.args)

			// Assertions
			if (err != nil) != tt.expectedError {
				t.Errorf("expected error: %v, got: %v", tt.expectedError, err)
			}
			if result != tt.expectedResult {
				t.Errorf("expected result: %v, got: %v", tt.expectedResult, result)
			}

			// Ensure all expectations were met
			err = mock.ExpectationsWereMet()
			require.NoError(t, err)
		})
	}
}

func TestAssignUserToRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	conf := ConfigACL{
		Database:     db,
		TableAccount: "users",
	}
	svc := NewService(conf)

	tests := []struct {
		name          string
		roleName      string
		mockRoleIDs   []uint
		expectedError bool
		mockFunc      func()
	}{
		{
			name:        "Successful assignment",
			roleName:    "Admin",
			mockRoleIDs: []uint{1},
			mockFunc: func() {
				// Mock query to get role IDs
				roleRows := sqlmock.NewRows([]string{"id"})
				for _, id := range []uint{1} {
					roleRows.AddRow(id)
				}
				mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM roles WHERE name IN (?)")).
					WithArgs("Admin").
					WillReturnRows(roleRows)

				// Mock query to assign role to user
				mock.ExpectExec(regexp.QuoteMeta("INSERT INTO user_has_roles (user_id, role_id) VALUES (?, ?)")).
					WithArgs(123, 1).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectedError: false,
		},
		{
			name:     "Error getting role ID",
			roleName: "Admin",
			mockFunc: func() {
				mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM roles WHERE name IN (?)")).
					WithArgs("Admin").
					WillReturnError(assert.AnError)
			},
			expectedError: true,
		},
		{
			name:        "Error assigning role to user",
			roleName:    "Admin",
			mockRoleIDs: []uint{1},
			mockFunc: func() {
				// Mock query to get role IDs
				roleRows := sqlmock.NewRows([]string{"id"})
				for _, id := range []uint{1} {
					roleRows.AddRow(id)
				}
				mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM roles WHERE name IN (?)")).
					WithArgs("Admin").
					WillReturnRows(roleRows)

				// Mock query to assign role to user
				mock.ExpectExec(regexp.QuoteMeta("INSERT INTO user_has_roles (user_id, role_id) VALUES (?, ?)")).
					WithArgs(123, 1).
					WillReturnError(assert.AnError)
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock expectations using mockFunc
			if tt.mockFunc != nil {
				tt.mockFunc()
			}

			// Call the service method
			err := svc.AssignUserToRole(context.Background(), 123, tt.roleName)

			// Assertions
			if (err != nil) != tt.expectedError {
				t.Errorf("expected error: %v, got: %v", tt.expectedError, err)
			}

			// Ensure all expectations were met
			err = mock.ExpectationsWereMet()
			require.NoError(t, err)
		})
	}
}
