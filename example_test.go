//go:build ignore
// +build ignore

package confide_acl_test

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/cangkir13/confide_acl"
)

var db *sql.DB

func init() {
	var err error
	dsn := ":memory:"
	db, err = sql.Open("mysql", dsn)

	if err != nil {
		log.Fatalf("failed to connect to the database: %v", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatalf("failed to ping the database: %v", err)
	}

	fmt.Println("Connected to the database")
}

// ExampleAddRole generates a role and stores it using the provided service.
//
// It creates a role  using the service provided.
func ExampleAddRole() {
	// init service
	svc := confide_acl.NewService(db)

	// Create a role
	err := svc.AddRole(context.Background(), "productor")
	if err != nil {
		log.Fatalf("failed to create role: %v", err)
	}

	// output nil if success
}

// ExampleAddPermission generates a permission and stores it using the provided service.
//
// It creates a permission using the service provided.
func ExampleAddPermission() {
	// init service
	svc := confide_acl.NewService(db)

	// Create a permission
	err := svc.AddPermission(context.Background(), "mybo.create")
	if err != nil {
		log.Fatalf("failed to create permission: %v", err)
	}

	// output nil if success
}

// ExampleAssignPermissionToRole assigns a permission to a role using the provided service.
//
// It assigns a permission to a role using the service provided.
func ExampleAssignPermissionToRole() {
	// init service
	svc := confide_acl.NewService(db)

	// Assign permission to role
	err := svc.AssignPermissionToRole(context.Background(), "productor", []string{"read", "mybo.create"})
	if err != nil {
		log.Fatalf("failed to assign permission to role: %v", err)
	}

	// output nil if success
}

// Example Middleware AuthACL
func ExampleMiddlewareACL() {
	// init service
	service := confide_acl.NewService(db)

	server := http.NewServeMux()
	server.HandleFunc("/", confideacl.AuthACL(service, "role:Admin|permission:Read"), HomeHandler)
	// or
	server.HandleFunc("/", confideacl.AuthACL(service, "role:Admin"), HomeHandler)

	// output next to HomeHandler
	http.ListenAndServe(":8080", server)
}
