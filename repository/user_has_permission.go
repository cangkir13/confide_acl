package repository

type UserHasPermission struct {
	UserID       uint `json:"user_id"`
	PermissionID uint `json:"permission_id"`
}
