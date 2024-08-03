[![Go Reference](https://pkg.go.dev/badge/github.com/cangkir13/confide_acl.svg)](https://pkg.go.dev/github.com/cangkir13/confide_acl)
[![CodeQL](https://github.com/cangkir13/confide_acl/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/cangkir13/confide_acl/actions/workflows/github-code-scanning/codeql)
[![Build](https://github.com/cangkir13/confide_acl/actions/workflows/go.yml/badge.svg)](https://github.com/cangkir13/confide_acl/actions/workflows/go.yml)


The `confide_acl` package is a Go library designed for managing roles and permissions in an application. This package provides functionalities to create roles and permissions, as well as assign permissions to roles.


## Installation

1. To add the `confide_acl` package to your Go project, run:

```sh
go get github.com/cangkir13/confide_acl
```
2. migration sql needed. you can download file below and import sql file manually to your Database
```sh
https://github.com/cangkir13/confide_acl/blob/main/migrations/20240801_initial.sql
```

## Usage
This is sample usage

```go
func main() {
	// Connect to the database driver
	db, err := sql.Open("mysql", "user:password@tcp(127.0.0.1:3306)/dbname")
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	// inject db connection
	confideAcl := confide_acl.NewService(db)

	// Create a role
	err = confideAcl.CreateRole(context.Background(), "admin")
	if err != nil {
		log.Fatalf("failed to create role: %v", err)
	}
}
```
## Arguments list
| Parameter | Type     | Example                |
| :-------- | :------- | :------------------------- |
| `name` | `string` | Read |
| `role` | `string` | Admin |
| `permissions` | `[]string` | []string{"Raad", "Create"} |
| `args`        | `string`    | "role:admin" or "role:admin,product" or "permission:Read" or "permission:Read,Create" |

**Note**: The pipe character `|` is used to combine multiple roles or permissions in the `args` parameter. example "role:admin|permission:Read" or multiple combine "role:admin,product|permission:Read"

#### Get item

## Functions list

### func AddRole
```go
func AddRole(ctx context.Context, name string) error
```
create new role example `Admin` or others for user role name

### func AddPermission
```go
func AddPermission(ctx context.Context, name string) error
```
create new permission example `Product.create` | `Product-create` | `Product-create`

### func AssignPermissionToRole
```go
func AssignPermissionToRole(ctx context.Context, role string, permissions []string) error
```
create new role example `Product.create` | `Product.update` | `Product.delete`

### func 
```go
func ValidateControl(ctx context.Context, args string) (bool, error)
```
<br/>

# Contact

For any inquiries or support, please contact cangkir13@gmail.com.