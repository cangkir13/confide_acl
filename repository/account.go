package repository

type Account struct {
	ID       uint   `json:"id"`
	Email    string `json:"email"`
	RoleName string `json:"role_name"`
	SQL      *SQL
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
