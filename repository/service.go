package repository

import (
	"context"
	"database/sql"
	"fmt"
)

type SQL struct {
	db *sql.DB
}

func NewSQL(db *sql.DB) *SQL {
	return &SQL{db: db}
}

func (sql *SQL) CreateRole(ctx context.Context, name string) error {
	query := "INSERT INTO roles (name) VALUES (?)"

	_, err := sql.db.ExecContext(ctx, query, name)
	if err != nil {
		return fmt.Errorf("failed to create role with name %s: %w", name, err)
	}
	return nil
}

func (sql *SQL) CreatePermission(ctx context.Context, name string) error {
	query := "INSERT INTO permissions (name) VALUES (?)"

	_, err := sql.db.ExecContext(ctx, query, name)
	if err != nil {
		return fmt.Errorf("failed to create permission with name %s: %w", name, err)
	}
	return nil
}
