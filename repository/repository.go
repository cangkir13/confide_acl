package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrDuplicatePermission = errors.New("duplicate permission")
	ErrDuplicateRole       = errors.New("duplicate role")
	ErrDuplicateUserRole   = errors.New("duplicate user role")
	ErrRoleNotFound        = errors.New("role not found")
	ErrPermissionNotFound  = errors.New("permission not found")
)

type SQL struct {
	db                  *sql.DB
	tableAccountDefault string
}

func NewSQL(db *sql.DB, tableAccountDefault string) SQL {
	return SQL{db: db, tableAccountDefault: tableAccountDefault}
}

type RepositoryService interface {
	CreateRole(ctx context.Context, name string) error
	CreatePermission(ctx context.Context, name string) error
	GetAccountHasPermission(ctx context.Context, userid uint, ps []string) ([]Permission, error)
	GetAccountHasRolePermissions(ctx context.Context, userid uint, roleID []uint) (RoleHasPermissions, error)
	GetPermissionIDByName(ctx context.Context, permissions []string) ([]uint, error)
	GetRoleIDByName(ctx context.Context, names []string) ([]uint, error)
	GivePermissionToRole(ctx context.Context, roleID uint, permissions []uint) error
	GiveRoleToUser(ctx context.Context, userID uint, roleID uint) error
}

// CreateRole inserts a new role into the database with the given name.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - name: The name of the role to be created.
//
// Returns:
// - error: An error if the role creation fails, otherwise nil.
func (sql *SQL) CreateRole(ctx context.Context, name string) error {
	query := "INSERT INTO roles (name) VALUES (?)"

	_, err := sql.db.ExecContext(ctx, query, name)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			return ErrDuplicateRole
		}
		return fmt.Errorf("failed to create role with name %s: %w", name, err)
	}
	return nil
}

// CreatePermission inserts a new permission into the database with the given name.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - name: The name of the permission to be created.
//
// Returns:
// - error: An error if the permission creation fails, otherwise nil.
func (sql *SQL) CreatePermission(ctx context.Context, name string) error {
	query := "INSERT INTO permissions (name) VALUES (?)"

	_, err := sql.db.ExecContext(ctx, query, name)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			return ErrDuplicatePermission
		}
		return fmt.Errorf("failed to create permission with name %s: %w", name, err)
	}
	return nil
}

// GetAccountRoleByID retrieves the account role associated with a user from the SQL database based on the user ID.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - userID: The ID of the user for whom the account role is being retrieved.
//
// Returns:
// - AccountRole: The account role associated with the user.
// - error: An error if the retrieval fails, otherwise nil.
func (s *SQL) GetAccountRoleByID(ctx context.Context, userID uint) (AccountRole, error) {
	var accountRole AccountRole
	query := `
		SELECT 
			a.full_name AS fullName, 
			r.name AS roleName 
		FROM 
			user_has_roles ur 
		JOIN 
			` + s.tableAccountDefault + ` a ON ur.user_id = a.id 
		JOIN 
			roles r ON ur.role_id = r.id 
		WHERE 
			a.id = ?
	`

	err := s.db.QueryRowContext(ctx, query, userID).Scan(&accountRole.FullName, &accountRole.RoleName)
	if err != nil && err != sql.ErrNoRows {
		return accountRole, err
	}

	return accountRole, nil
}

// GetPermissionIDByName retrieves the permission IDs from the database based on the provided permission names.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - permissions: A slice of strings representing the permission names.
//
// Returns:
// - []uint: A slice of uint representing the permission IDs.
// - error: An error if the query fails, otherwise nil.
func (sql *SQL) GetPermissionIDByName(ctx context.Context, permissions []string) ([]uint, error) {
	var permissionIDs []uint

	// Bangun query SQL dengan placeholder untuk setiap permission name
	placeholders := make([]string, len(permissions))
	args := make([]interface{}, len(permissions))

	for i, perm := range permissions {
		placeholders[i] = "?"
		args[i] = perm
	}

	query := fmt.Sprintf("SELECT id FROM permissions WHERE name IN (%s)",
		strings.Join(placeholders, ","))

	// Eksekusi query dan proses hasil
	rows, err := sql.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query permissions: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var permissionID uint
		if err := rows.Scan(&permissionID); err != nil {
			return nil, fmt.Errorf("failed to scan permission ID: %w", err)
		}
		permissionIDs = append(permissionIDs, permissionID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through rows: %w", err)
	}

	if len(permissionIDs) == 0 {
		return nil, ErrPermissionNotFound
	}

	return permissionIDs, nil
}

// GetRoleIDByName retrieves the IDs of roles based on their names from the database.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - roles: A slice of strings representing the role names.
//
// Returns:
// - []uint: A slice of uint representing the role IDs.
// - error: An error if the query fails, otherwise nil.
func (sql *SQL) GetRoleIDByName(ctx context.Context, roles []string) ([]uint, error) {
	var roleIDs []uint

	// Bangun query SQL dengan placeholder untuk setiap role name
	placeholders := make([]string, len(roles))
	args := make([]interface{}, len(roles))

	for i, role := range roles {
		placeholders[i] = "?"
		args[i] = role
	}

	query := fmt.Sprintf("SELECT id FROM roles WHERE name IN (%s)",
		strings.Join(placeholders, ","))

	// Eksekusi query dan proses hasil
	rows, err := sql.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query roles: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var roleID uint
		if err := rows.Scan(&roleID); err != nil {
			return nil, fmt.Errorf("failed to scan role ID: %w", err)
		}
		roleIDs = append(roleIDs, roleID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through rows: %w", err)
	}

	if len(roleIDs) == 0 {
		return nil, ErrRoleNotFound
	}

	return roleIDs, nil
}

func (s *SQL) GetAccountHasPermission(ctx context.Context, userid uint, ps []string) ([]Permission, error) {
	var permissions []Permission

	baseQuery := `SELECT p.id, p.name
				FROM user_has_permissions uhp
				JOIN permissions p ON uhp.permission_id = p.id
				WHERE uhp.user_id = ?`

	// Prepare query based on roles length
	var query string
	var args []interface{}
	args = append(args, userid)

	placeholders := make([]string, len(ps))
	for i := range placeholders {
		placeholders[i] = "?"
	}

	placeholdersStr := strings.Join(placeholders, ", ")
	query = baseQuery + ` AND p.name IN (` + placeholdersStr + `)`
	args = append(args, convertStringSliceToInterfaceSlice(ps)...)

	// execute query
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var permission Permission
		if err := rows.Scan(&permission.ID, &permission.Name); err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

// GetAccountHasRolePermissions retrieves the role permissions associated with a user from the SQL database.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - userid: The ID of the user for whom the role permissions are being retrieved.
// - roles: A slice of strings representing the names of the roles to be retrieved.
//
// Returns:
// - RoleHasPermissions: A struct containing the role ID and a slice of Permission structs representing the role permissions.
// - error: An error if the retrieval fails, otherwise nil.
func (sql *SQL) GetAccountHasRolePermissions(ctx context.Context, userid uint, roles []string) (RoleHasPermissions, error) {
	var rolePermissions RoleHasPermissions
	var permissions []Permission

	baseQuery := `SELECT r.id, p.id, p.name
				FROM user_has_roles ur
				JOIN roles r ON ur.role_id = r.id
				JOIN role_has_permissions rhp ON rhp.role_id = r.id
				JOIN permissions p ON rhp.permission_id = p.id
				WHERE ur.user_id = ? `

	// Prepare query based on roles length
	var query string
	var args []interface{}
	args = append(args, userid)

	placeholders := make([]string, len(roles))
	for i := range placeholders {
		placeholders[i] = "?"
	}

	placeholdersStr := strings.Join(placeholders, ", ")
	query = baseQuery + ` AND r.name IN (` + placeholdersStr + `)`
	args = append(args, convertStringSliceToInterfaceSlice(roles)...)

	// Execute query
	rows, err := sql.db.QueryContext(ctx, query, args...)
	if err != nil {
		return rolePermissions, err
	}
	defer rows.Close()

	var roleid uint
	for rows.Next() {
		var permission Permission
		if err := rows.Scan(&roleid, &permission.ID, &permission.Name); err != nil {
			return rolePermissions, err
		}
		permissions = append(permissions, permission)
	}

	if err := rows.Err(); err != nil {
		return rolePermissions, err
	}

	// Assuming only one role ID is returned
	if len(permissions) > 0 {
		rolePermissions.RoleID = roleid
	}
	rolePermissions.Permission = permissions

	return rolePermissions, nil
}

// GivePermissionToRole assigns a list of permissions to a role in the SQL database.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - roleID: The ID of the role to which the permissions will be assigned.
// - permissions: A slice of uint representing the IDs of the permissions to be assigned.
//
// Returns:
// - error: An error if the assignment fails, otherwise nil.
func (sql *SQL) GivePermissionToRole(ctx context.Context, roleID uint, permissions []uint) error {
	// Mulai transaksi
	tx, err := sql.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}

	// Persiapkan query untuk memasukkan izin
	query := "INSERT INTO role_has_permissions (role_id, permission_id) VALUES (?, ?)"
	for _, permissionID := range permissions {
		_, err := tx.ExecContext(ctx, query, roleID, permissionID)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to assign permission %d to role %d: %w", permissionID, roleID, err)
		}
	}

	// Commit transaksi
	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GiveRoleToUser assigns a role to a user in the database.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - userID: The ID of the user to whom the role will be assigned.
// - role: The ID of the role to be assigned to the user.
//
// Returns:
// - error: An error if the assignment fails, otherwise nil.
func (sql *SQL) GiveRoleToUser(ctx context.Context, userID uint, role uint) error {
	query := "INSERT INTO user_has_roles (user_id, role_id) VALUES (?, ?)"

	_, err := sql.db.ExecContext(ctx, query, userID, role)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			return ErrDuplicateUserRole
		}
		return fmt.Errorf("failed to assign role %d to user %d: %w", role, userID, err)
	}
	return nil
}

// Helper function to convert []sting to []interface{}
func convertStringSliceToInterfaceSlice(slice []string) []interface{} {
	result := make([]interface{}, len(slice))
	for i, v := range slice {
		result[i] = v
	}
	return result
}
