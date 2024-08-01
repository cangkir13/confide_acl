# Overview 

The `confide_acl` package is a Go library designed for managing roles and permissions in an application. This package provides functionalities to create roles and permissions, as well as assign permissions to roles.


## Installation

1. To add the `confide_acl` package to your Go project, run:

```sh
go get github.com/cangkir13/confide_acl
```
2. migration sql needed. you can download file below and migration manually on your DATABASE
```sh
https://github.com/cangkir13/confide_acl/blob/main/migrations/20240801_initial.sql
```

## Usage

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


## Functions list

### func SetRole
```go
func SetRole(ctx context.Context, name string) error
```
create new role example `Admin` or others for user role name

### func SetPermission
```go
func SetPermission(ctx context.Context, name string) error
```
create new permission example `Product.create` | `Product.update` | `Product.delete`

### func AssignPermissionToRole
```go
func AssignPermissionToRole(ctx context.Context, role string, permissions []string) error
```
create new role example `Product.create` | `Product.update` | `Product.delete`

<br/>

# Contact

For any inquiries or support, please contact cangkir13@gmail.com.