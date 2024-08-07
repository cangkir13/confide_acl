package repository_test

import (
	"context"
	"reflect"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/cangkir13/confide_acl/repository"
)

var tableuser string = "users"

func TestCreateRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	repo := repository.NewSQL(db, tableuser)
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

	repo := repository.NewSQL(db, tableuser)
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

	repo := repository.NewSQL(db, tableuser)
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

func TestGiveRoleToUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	tablename := "custom_table"
	repo := repository.NewSQL(db, tablename)
	ctx := context.Background()
	userID := uint(1)
	roleID := uint(2)

	// Test case: Successful role assignment with a user_has_roles table name
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO user_has_roles (user_id, role_id) VALUES (?, ?)")).
		WithArgs(userID, roleID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := repo.GiveRoleToUser(ctx, userID, roleID); err != nil {
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

	repo := repository.NewSQL(db, tableuser)
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

func TestGetRoleAccountByID(t *testing.T) {
	tests := []struct {
		name        string
		userid      uint
		setupMocks  func(mock sqlmock.Sqlmock)
		expected    repository.AccountRole
		expectError bool
	}{
		{
			name:   "Valid role ID",
			userid: 1,
			setupMocks: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name"}).
					AddRow("admin", "admin")
				mock.ExpectQuery(regexp.QuoteMeta(
					`SELECT  a.full_name AS fullName,  r.name AS roleName FROM  user_has_roles ur 
					JOIN users a ON ur.user_id = a.id 
					JOIN roles r ON ur.role_id = r.id  WHERE  a.id = ?`,
				)).
					WithArgs(1).
					WillReturnRows(rows)
			},
			expected: repository.AccountRole{
				FullName: "admin",
				RoleName: "admin",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
			}
			defer db.Close()

			repo := repository.NewSQL(db, tableuser)
			ctx := context.Background()

			tt.setupMocks(mock)

			roles, err := repo.GetAccountRoleByID(ctx, tt.userid)

			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}

			if !reflect.DeepEqual(roles, tt.expected) {
				t.Errorf("expected: %v, got: %v", tt.expected, roles)
			}
		})
	}
}

func TestGetPermissionIDByName(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	repo := repository.NewSQL(db, tableuser)
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

func TestGetAccountRole(t *testing.T) {
	tests := []struct {
		name        string
		userid      uint
		roleid      []uint
		setupMocks  func(mock sqlmock.Sqlmock)
		expected    []repository.AccountRole
		expectError bool
	}{
		{
			name:   "Successful query with one role",
			userid: 1,
			roleid: []uint{1},
			setupMocks: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"full_name", "role_name"}).
					AddRow("John Doe", "admin")

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT a.full_name, r.name AS role_name FROM user_has_roles ur JOIN users a ON ur.user_id = a.id JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ? AND ur.role_id = ?`)).
					WithArgs(1, 1).
					WillReturnRows(rows)
			},
			expected: []repository.AccountRole{
				{FullName: "John Doe", RoleName: "admin"},
			},
			expectError: false,
		},
		{
			name:   "Successful query with multiple roles",
			userid: 1,
			roleid: []uint{1, 2},
			setupMocks: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"full_name", "role_name"}).
					AddRow("John Doe", "admin").
					AddRow("Jane Smith", "user")

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT a.full_name, r.name AS role_name FROM user_has_roles ur JOIN users a ON ur.user_id = a.id JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ? AND ur.role_id IN (?, ?)`)).
					WithArgs(1, 1, 2).
					WillReturnRows(rows)
			},
			expected: []repository.AccountRole{
				{FullName: "John Doe", RoleName: "admin"},
				{FullName: "Jane Smith", RoleName: "user"},
			},
			expectError: false,
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

			sqlInstance := repository.NewSQL(db, "users")

			ctx := context.Background()
			result, err := sqlInstance.GetAccountRole(ctx, tt.userid, tt.roleid)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("expected result: %v, got: %v", tt.expected, result)
			}
		})
	}
}

func TestGetAccountPermission(t *testing.T) {
	tests := []struct {
		name         string
		userid       uint
		permissionid []uint
		setupMocks   func(mock sqlmock.Sqlmock)
		expected     []repository.AccountPermission
		expectError  bool
	}{
		{
			name:         "Successful query with one permission",
			userid:       1,
			permissionid: []uint{1},
			setupMocks: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"full_name", "permission_name"}).
					AddRow("John Doe", "edit")

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT a.full_name, p.name AS permission_name FROM user_has_permissions up JOIN users a ON up.user_id = a.id JOIN permissions p ON up.permission_id = p.id WHERE up.user_id = ? AND up.permission_id IN (?)`)).
					WithArgs(1, 1).
					WillReturnRows(rows)
			},
			expected: []repository.AccountPermission{
				{FullName: "John Doe", PermissionName: "edit"},
			},
			expectError: false,
		},
		{
			name:         "Successful query with multiple permissions",
			userid:       1,
			permissionid: []uint{1, 2},
			setupMocks: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"full_name", "permission_name"}).
					AddRow("John Doe", "edit").
					AddRow("John Doe", "delete")

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT a.full_name, p.name AS permission_name FROM user_has_permissions up JOIN users a ON up.user_id = a.id JOIN permissions p ON up.permission_id = p.id WHERE up.user_id = ? AND up.permission_id IN (?, ?)`)).
					WithArgs(1, 1, 2).
					WillReturnRows(rows)
			},
			expected: []repository.AccountPermission{
				{FullName: "John Doe", PermissionName: "edit"},
				{FullName: "John Doe", PermissionName: "delete"},
			},
			expectError: false,
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

			sqlInstance := repository.NewSQL(db, "users")

			ctx := context.Background()
			result, err := sqlInstance.GetAccountPermission(ctx, tt.userid, tt.permissionid)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("expected result: %v, got: %v", tt.expected, result)
			}
		})
	}
}
