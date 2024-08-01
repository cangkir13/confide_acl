package repository

type RoleHasPermission struct {
	RoleID       uint `json:"role_id"`
	PermissionID uint `json:"permission_id"`
}
