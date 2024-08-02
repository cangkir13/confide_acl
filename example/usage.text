package main

import (
	"context"
	"database/sql"
	"log"

	confide_acl "github.com/cangkir13/confide_acl"
	_ "github.com/go-sql-driver/mysql" // Import driver database
)

func main() {
	// Connect to the database
	db, err := sql.Open("mysql", "root:1@tcp(127.0.0.1:3306)/confide_acl?parseTime=true")
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create a new repository and service and inject the database connection
	svc := confide_acl.NewService(db)

	// Create a role
	err = svc.SetRole(context.Background(), "productor")
	if err != nil {
		log.Fatalf("failed to create role: %v", err)
	}

	// Create a permission
	err = svc.SetPermission(context.Background(), "mybo.create")
	if err != nil {
		log.Fatalf("failed to create permission: %v", err)
	}

	// Assign permission to role
	err = svc.AssignPermissionToRole(context.Background(), "productor", []string{"read", "mybo.create"})
	if err != nil {
		log.Fatalf("failed to assign permission to role: %v", err)
	}

	// check has permission or role
	// example: "role:Admin" or "permission:mybo.create"
	// or combined "role:Admin|permission:mybo.create"
	// or multiple flag "role:Admin|permission:mybo.create,mybo.read"
	has, err := svc.ValidateControl(context.Background(), "role:Admin")
	if err != nil {
		log.Fatalf("failed to validate control: %v", err)
	}

	log.Printf("has permission: %v", has)

}
