package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type SQL struct {
	db *sql.DB
}

func NewSQL(db *sql.DB) *SQL {
	return &SQL{db: db}
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
		return fmt.Errorf("failed to create permission with name %s: %w", name, err)
	}
	return nil
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

	return roleIDs, nil
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

	return permissionIDs, nil
}

func (sql *SQL) CheckRolePermission(ctx context.Context, roleID []uint, permissionID []uint) (bool, error) {
	query := "SELECT COUNT(*) FROM role_has_permissions WHERE "
	conditions := []string{}

	// Add role condition if roles are provided
	if len(roleID) > 0 {
		rolePlaceholders := make([]string, len(roleID))
		for i := range roleID {
			rolePlaceholders[i] = "?"
		}
		conditions = append(conditions, fmt.Sprintf("role_id IN (%s)", strings.Join(rolePlaceholders, ",")))
	}

	// Add permission condition if permissions are provided
	if len(permissionID) > 0 {
		permissionPlaceholders := make([]string, len(permissionID))
		for i := range permissionID {
			permissionPlaceholders[i] = "?"
		}
		conditions = append(conditions, fmt.Sprintf("permission_id IN (%s)", strings.Join(permissionPlaceholders, ",")))
	}

	query += strings.Join(conditions, " AND ")

	fmt.Println("query:", query)
	// Create a single slice of arguments from roleID and permissionID slices
	args := []interface{}{}
	for _, id := range roleID {
		args = append(args, id)
	}
	for _, id := range permissionID {
		args = append(args, id)
	}

	rows, err := sql.db.QueryContext(ctx, query, args...)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	var count int
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			return false, err
		}
	}

	return count > 0, nil
}
