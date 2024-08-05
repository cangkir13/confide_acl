package repository

type Account struct {
	ID       uint   `json:"id"`
	FullName string `json:"full_name"`
	Email    string `json:"email"`
	RoleName string `json:"role_name"`
	SQL      *SQL
}

type AccountRole struct {
	FullName string `json:"full_name"`
	RoleName string `json:"role_name"`
}

type AccountPermission struct {
	FullName       string `json:"full_name"`
	PermissionName string `json:"permission_name"`
}

// TableName returns the name of the table for the Account struct.
//
// If the SQL tableAccountDefault field is not nil, it returns the value of the field.
// Otherwise, it returns the string "users".
//
// Returns:
// - string: the name of the table.
func (a *Account) TableName() string {
	if a.SQL.tableAccountDefault != "" {
		return a.SQL.tableAccountDefault
	}
	return "users"
}
