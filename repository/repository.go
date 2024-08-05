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

// GetAccountPermission retrieves the account permissions associated with a user from the SQL database.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - userid: The ID of the user for whom the permissions are being retrieved.
// - permissionid: A slice of uint representing the IDs of the permissions to be retrieved.
//
// Returns:
// - []AccountPermission: A slice of AccountPermission structs representing the account permissions associated with the user.
// - error: An error if the retrieval fails, otherwise nil.
func (sql *SQL) GetAccountPermission(ctx context.Context, userid uint, permissionid []uint) ([]AccountPermission, error) {
	// Base query
	baseQuery := `
		SELECT
			a.full_name,
			p.name AS permission_name
		FROM
			user_has_permissions up
		JOIN
			` + sql.tableAccountDefault + ` a ON up.user_id = a.id
		JOIN
			permissions p ON up.permission_id = p.id
		WHERE
			up.user_id = ?
	`

	// Prepare query based on permissionid length
	var query string
	var args []interface{}
	args = append(args, userid)

	if len(permissionid) > 0 {
		// Multiple permission IDs
		placeholders := make([]string, len(permissionid))
		for i := range placeholders {
			placeholders[i] = "?"
		}
		placeholdersStr := strings.Join(placeholders, ", ")
		query = baseQuery + ` AND up.permission_id IN (` + placeholdersStr + `)`
		args = append(args, convertUintSliceToInterfaceSlice(permissionid)...)
	} else {
		// No permission ID provided, use the base query without additional conditions
		query = baseQuery
	}

	// Execute the query
	rows, err := sql.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Process results
	var results []AccountPermission
	for rows.Next() {
		var accountPermission AccountPermission
		if err := rows.Scan(&accountPermission.FullName, &accountPermission.PermissionName); err != nil {
			return nil, err
		}
		results = append(results, accountPermission)
	}

	// Check for any row errors
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// GetAccountRole retrieves the account roles associated with a user from the SQL database.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - userid: The ID of the user for whom the roles are being retrieved.
// - roleid: A slice of uint representing the IDs of the roles to be retrieved.
//
// Returns:
// - []AccountRole: A slice of AccountRole structs representing the account roles associated with the user.
// - error: An error if the retrieval fails, otherwise nil.
func (sql *SQL) GetAccountRole(ctx context.Context, userid uint, roleid []uint) ([]AccountRole, error) {
	// Base query
	baseQuery := `
        SELECT
            a.full_name,
            a.role_name
        FROM
            user_has_roles ur
        JOIN
            ` + sql.tableAccountDefault + ` a ON ur.user_id = a.id
        WHERE
            ur.user_id = ?
    `

	// Prepare query based on roleid length
	var query string
	var args []interface{}
	args = append(args, userid)

	if len(roleid) > 1 {
		// Multiple role IDs
		placeholders := make([]string, len(roleid))
		for i := range placeholders {
			placeholders[i] = "?"
		}
		placeholdersStr := strings.Join(placeholders, ", ")
		query = baseQuery + ` AND ur.role_id IN (` + placeholdersStr + `)`
		args = append(args, convertUintSliceToInterfaceSlice(roleid)...)
	} else if len(roleid) == 1 {
		// Single role ID
		query = baseQuery + ` AND ur.role_id = ?`
		args = append(args, roleid[0])
	} else {
		// No role ID provided, should not happen based on requirements
		return nil, errors.New("roleid cannot be empty")
	}

	// Execute the query
	rows, err := sql.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Process results
	var results []AccountRole
	for rows.Next() {
		var accountRole AccountRole
		if err := rows.Scan(&accountRole.FullName, &accountRole.RoleName); err != nil {
			return nil, err
		}
		results = append(results, accountRole)
	}

	// Check for any row errors
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
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

// Helper function to convert []uint to []interface{}
func convertUintSliceToInterfaceSlice(slice []uint) []interface{} {
	result := make([]interface{}, len(slice))
	for i, v := range slice {
		result[i] = v
	}
	return result
}
