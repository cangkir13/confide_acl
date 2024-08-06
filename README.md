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

	dsn := "root:1@tcp(127.0.0.1:3306)/sibos"
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// you can custom to other table
	// default table is `users`
	defaulttable := "admin"

	// configure acl db and table default user
	configacl := confide_acl.ConfigACL{
		Database:     db,
		TableAccount: defaulttable,
	}

	acl := confide_acl.NewService(configacl)

	// test mux route
	r := mux.NewRouter()
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World"))
	})

	admin := r.PathPrefix("").Subrouter()
	admin.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello Admin"))
	})

	admin.HandleFunc("/add_permission", func(w http.ResponseWriter, r *http.Request) {
		// you can call json decode here
		permission := r.FormValue("permission")
		err = acl.AddPermission(context.Background(), permission)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
		}
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
		}
		w.Write([]byte("new permission has been added"))
	}).Methods("POST")

	admin.HandleFunc("/add_role", func(w http.ResponseWriter, r *http.Request) {
		// you can call json decode here
		role := r.FormValue("role")
		err := acl.AddRole(context.Background(), role)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
		}
		w.Write([]byte("new role has been added"))
	}).Methods("POST")

	r.Use(AuthACL(acl, "role:Superadmin"))
	admin.Use(AuthACL(acl, "role:Admin"))

	http.ListenAndServe(":8080", r)
}

// example middleware 
// args: you need declare with string "role:admin" or with multiple "role:superadmin,admin" (its mean superadmin or admin role)
// or you can notice with permission list "permission:read" in this case is for special case
// or you can combine with `|` example "role:admin|permission:read" its mean allow role with admin or has permiission read
func AuthACL(s confide_acl.ConfideACL, args string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// adding user id
			userid := 2
			hasrole, err := s.PolicyACL(r.Context(), userid, args)
			if err != nil {
				confide.JSON(w, confide.Payload{
					Code:    confide.FCodeUnauthorized,
					Message: err.Error(),
				})
				return
			}
			if !hasrole {
				confide.JSON(w, confide.Payload{
					Code:    confide.FCodeUnauthorized,
					Message: "Unauthorized",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

```

# Contact

For any inquiries or support, please contact cangkir13@gmail.com.