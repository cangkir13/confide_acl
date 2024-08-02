package repository_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cangkir13/confide_acl/repository"
)

func TestCreateRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	repo := repository.NewSQL(db)
	ctx := context.Background()
	roleName := "admin"

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO roles (name) VALUES (?)")).
		WithArgs(roleName).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.CreateRole(ctx, roleName); err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestCreatePermission(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	repo := repository.NewSQL(db)
	ctx := context.Background()
	permissionName := "edit"

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO permissions (name) VALUES (?)")).
		WithArgs(permissionName).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.CreatePermission(ctx, permissionName); err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestGivePermissionToRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	repo := repository.NewSQL(db)
	ctx := context.Background()
	roleID := uint(1)
	permissions := []uint{1, 2, 3}

	mock.ExpectBegin()
	for _, permID := range permissions {
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO role_has_permissions (role_id, permission_id) VALUES (?, ?)")).
			WithArgs(roleID, permID).
			WillReturnResult(sqlmock.NewResult(1, 1))
	}
	mock.ExpectCommit()

	if err := repo.GivePermissionToRole(ctx, roleID, permissions); err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestGetRoleIDByName(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	repo := repository.NewSQL(db)
	ctx := context.Background()
	roleNames := []string{"admin", "user"}
	expectedRoleIDs := []uint{1, 2}

	rows := sqlmock.NewRows([]string{"id"}).AddRow(expectedRoleIDs[0]).AddRow(expectedRoleIDs[1])
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM roles WHERE name IN (?,?)")).
		WithArgs(roleNames[0], roleNames[1]).
		WillReturnRows(rows)

	roleIDs, err := repo.GetRoleIDByName(ctx, roleNames)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if len(roleIDs) != len(expectedRoleIDs) {
		t.Errorf("expected %v, got %v", expectedRoleIDs, roleIDs)
	}

	for i, id := range roleIDs {
		if id != expectedRoleIDs[i] {
			t.Errorf("expected role ID %d, got %d", expectedRoleIDs[i], id)
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestGetPermissionIDByName(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	repo := repository.NewSQL(db)
	ctx := context.Background()
	permissionNames := []string{"edit", "delete"}
	expectedPermissionIDs := []uint{1, 2}

	rows := sqlmock.NewRows([]string{"id"}).AddRow(expectedPermissionIDs[0]).AddRow(expectedPermissionIDs[1])
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM permissions WHERE name IN (?,?)")).
		WithArgs(permissionNames[0], permissionNames[1]).
		WillReturnRows(rows)

	permissionIDs, err := repo.GetPermissionIDByName(ctx, permissionNames)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if len(permissionIDs) != len(expectedPermissionIDs) {
		t.Errorf("expected %v, got %v", expectedPermissionIDs, permissionIDs)
	}

	for i, id := range permissionIDs {
		if id != expectedPermissionIDs[i] {
			t.Errorf("expected permission ID %d, got %d", expectedPermissionIDs[i], id)
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestCheckRolePermission(t *testing.T) {
	tests := []struct {
		name           string
		roleID         []uint
		permissionID   []uint
		setupMocks     func(mock sqlmock.Sqlmock)
		expectedResult bool
		expectError    bool
	}{
		{
			name:         "Valid role and permission",
			roleID:       []uint{1},
			permissionID: []uint{1},
			setupMocks: func(mock sqlmock.Sqlmock) {
				// role and permission rows
				mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM role_has_permissions WHERE role_id IN (?) AND permission_id IN (?)")).
					WithArgs(1, 1).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
			},
			expectedResult: true,
			expectError:    false,
		},
		{
			name:         "Valid multiple roles and permissions",
			roleID:       []uint{1, 2},
			permissionID: []uint{3, 4},
			setupMocks: func(mock sqlmock.Sqlmock) {
				// role and permission rows
				mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM role_has_permissions WHERE role_id IN (?,?) AND permission_id IN (?,?)")).
					WithArgs(1, 2, 3, 4).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
			},
			expectedResult: true,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
			}
			defer db.Close()

			tt.setupMocks(mock)

			sqlInstance := repository.NewSQL(db)

			ctx := context.Background()
			result, err := sqlInstance.CheckRolePermission(ctx, tt.roleID, tt.permissionID)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
				return
			}

			if result != tt.expectedResult {
				t.Errorf("expected result: %v, got: %v", tt.expectedResult, result)
			}
		})
	}
}
