package repository

type Role struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

type RoleHasPermissions struct {
	RoleID     uint         `json:"role_id"`
	Permission []Permission `json:"permissions"`
}
