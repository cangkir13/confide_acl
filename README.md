# Confide ACL (Access control list)
[![Go Reference](https://pkg.go.dev/badge/github.com/cangkir13/confide_acl.svg)](https://pkg.go.dev/github.com/cangkir13/confide_acl)
[![CodeQL](https://github.com/cangkir13/confide_acl/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/cangkir13/confide_acl/actions/workflows/github-code-scanning/codeql)
[![Build](https://github.com/cangkir13/confide_acl/actions/workflows/build.yml/badge.svg)](https://github.com/cangkir13/confide_acl/actions/workflows/build.yml)


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
#### ***Note***
* adding field `role_name` as `string` to your current users table
* setup REFERENCES foreign key for table `user_has_roles` and `user_has_permissions` to your users table

## Usage
This is sample usage

```go
func main() {

	// setup default table for user 
	// the default table account is "users"
	defautltUser := "admin"

	// inject db connection
	configacl := confide_acl.ConfigACL{
		Database:     db,
		TableAccount: defaulttable,
	}
	confideAcl := confide_acl.NewService(db, defautltUser)

	// Create a role
	err := confideAcl.AddRole(context.Background(), "admin")
	if err != nil {
		fmt.Println(err)
	}
}
```

# Contact

For any inquiries or support, please contact cangkir13@gmail.com.