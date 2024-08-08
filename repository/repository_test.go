package repository_test

import (
	"context"
	"database/sql"
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

func TestGetAccountHasPermission(t *testing.T) {
	tests := []struct {
		name        string
		userid      uint
		permissions []string
		setupMocks  func(mock sqlmock.Sqlmock)
		expected    []repository.Permission
		expectError bool
	}{
		{
			name:        "Successful query with one permission",
			userid:      1,
			permissions: []string{"edit"},
			setupMocks: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name"}).
					AddRow(1, "edit")

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT p.id, p.name
				FROM user_has_permissions uhp
				JOIN permissions p ON uhp.permission_id = p.id
				WHERE uhp.user_id = ? AND p.name IN (?)`)).
					WithArgs(1, "edit").
					WillReturnRows(rows)
			},
			expected: []repository.Permission{
				{ID: 1, Name: "edit"},
			},
			expectError: false,
		},
		{
			name:        "Successful query with multiple permissions",
			userid:      1,
			permissions: []string{"edit", "delete"},
			setupMocks: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"id", "name"}).
					AddRow(1, "edit").
					AddRow(2, "delete")

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT p.id, p.name
				FROM user_has_permissions uhp
				JOIN permissions p ON uhp.permission_id = p.id
				WHERE uhp.user_id = ? AND p.name IN (?, ?)`)).
					WithArgs(1, "edit", "delete").
					WillReturnRows(rows)
			},
			expected: []repository.Permission{
				{ID: 1, Name: "edit"},
				{ID: 2, Name: "delete"},
			},
			expectError: false,
		},
		{
			name:        "Query fails",
			userid:      1,
			permissions: []string{"edit"},
			setupMocks: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT p.id, p.name
				FROM user_has_permissions uhp
				JOIN permissions p ON uhp.permission_id = p.id
				WHERE uhp.user_id = ? AND p.name IN (?)`)).
					WithArgs(1, "edit").
					WillReturnError(sqlmock.ErrCancelled)
			},
			expected:    nil,
			expectError: true,
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
			result, err := sqlInstance.GetAccountHasPermission(ctx, tt.userid, tt.permissions)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("expected result: %v, got: %v", tt.expected, result)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}

func TestGetAccountHasRolePermissions(t *testing.T) {
	tests := []struct {
		name        string
		userid      uint
		roles       []string
		setupMocks  func(mock sqlmock.Sqlmock)
		expected    repository.RoleHasPermissions
		expectError bool
	}{
		{
			name:   "Successful query with one role",
			userid: 1,
			roles:  []string{"admin"},
			setupMocks: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"r.id", "p.id", "p.name"}).
					AddRow(1, 1, "admin.post").
					AddRow(1, 2, "admin.get")

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT r.id, p.id, p.name
					FROM user_has_roles ur
					JOIN roles r ON ur.role_id = r.id
					JOIN role_has_permissions rhp ON rhp.role_id = r.id
					JOIN permissions p ON rhp.permission_id = p.id
					WHERE ur.user_id = ? AND r.name IN (?)`)).
					WithArgs(1, "admin").
					WillReturnRows(rows)
			},
			expected: repository.RoleHasPermissions{
				RoleID: 1,
				Permission: []repository.Permission{
					{ID: 1, Name: "admin.post"},
					{ID: 2, Name: "admin.get"},
				},
			},
			expectError: false,
		},
		{
			name:   "Successful query with multiple roles",
			userid: 1,
			roles:  []string{"admin", "user"},
			setupMocks: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"r.id", "p.id", "p.name"}).
					AddRow(1, 1, "admin.post").
					AddRow(1, 2, "admin.get").
					AddRow(2, 3, "user.view")

				mock.ExpectQuery(regexp.QuoteMeta(`SELECT r.id, p.id, p.name
					FROM user_has_roles ur
					JOIN roles r ON ur.role_id = r.id
					JOIN role_has_permissions rhp ON rhp.role_id = r.id
					JOIN permissions p ON rhp.permission_id = p.id
					WHERE ur.user_id = ? AND r.name IN (?, ?)`)).
					WithArgs(1, "admin", "user").
					WillReturnRows(rows)
			},
			expected: repository.RoleHasPermissions{
				RoleID: 2,
				Permission: []repository.Permission{
					{ID: 1, Name: "admin.post"},
					{ID: 2, Name: "admin.get"},
					{ID: 3, Name: "user.view"},
				},
			},
			expectError: false,
		},
		{
			name:   "Query returns no rows",
			userid: 1,
			roles:  []string{"nonexistent_role"},
			setupMocks: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"r.id", "p.id", "p.name"})
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT r.id, p.id, p.name
					FROM user_has_roles ur
					JOIN roles r ON ur.role_id = r.id
					JOIN role_has_permissions rhp ON rhp.role_id = r.id
					JOIN permissions p ON rhp.permission_id = p.id
					WHERE ur.user_id = ? AND r.name IN (?)`)).
					WithArgs(1, "nonexistent_role").
					WillReturnRows(rows)
			},
			expected: repository.RoleHasPermissions{
				RoleID:     0,
				Permission: nil,
			},
			expectError: false,
		},
		{
			name:   "Query returns an error",
			userid: 1,
			roles:  []string{"admin"},
			setupMocks: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT r.id, p.id, p.name
					FROM user_has_roles ur
					JOIN roles r ON ur.role_id = r.id
					JOIN role_has_permissions rhp ON rhp.role_id = r.id
					JOIN permissions p ON rhp.permission_id = p.id
					WHERE ur.user_id = ? AND r.name IN (?)`)).
					WithArgs(1, "admin").
					WillReturnError(sql.ErrConnDone)
			},
			expected: repository.RoleHasPermissions{
				RoleID:     0,
				Permission: nil,
			},
			expectError: true,
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

			sqlInstance := repository.NewSQL(db, tableuser)

			ctx := context.Background()
			result, err := sqlInstance.GetAccountHasRolePermissions(ctx, tt.userid, tt.roles)
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
