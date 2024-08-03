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

## Usage
This is sample usage

```go
func main() {

	// inject db connection
	confideAcl := confide_acl.NewService(db)

	// Create a role
	err := confideAcl.CreateRole(context.Background(), "admin")
	if err != nil {
		fmt.Println(err)
	}
}
```

# Contact

For any inquiries or support, please contact cangkir13@gmail.com.