package confide_acl

import (
	"context"
	"database/sql"
	"strings"

	"github.com/cangkir13/confide_acl/repository"
)

type service struct {
	repo repository.SQL
}

// AddRole sets a new role in the system.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - name: The name of the role to be created.
//
// Returns:
// - error: An error if the role creation fails, otherwise nil.
func (s *service) AddRole(ctx context.Context, name string) error {
	err := s.repo.CreateRole(ctx, name)
	if err != nil {
		return err
	}
	return nil
}

// AddPermission sets a new permission in the system.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - name: The name of the permission to be created.
//
// Returns:
// - error: An error if the permission creation fails, otherwise nil.
//
// Example:
//
//	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//
// defer cancel()
//
//	if err := service.AddPermission(ctx, "create_user"); err != nil {
//		log.Fatalf("failed to create permission: %v", err)
//	}
func (s *service) AddPermission(ctx context.Context, name string) error {
	err := s.repo.CreatePermission(ctx, name)
	if err != nil {
		return err
	}
	return nil
}

// AssignPermissionToRole assigns a list of permissions to a role in the system.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - role: The name of the role to which the permissions will be assigned.
// - permissions: A slice of strings representing the names of the permissions to be assigned.
//
// Returns:
// - error: An error if the assignment fails, otherwise nil.
func (s *service) AssignPermissionToRole(ctx context.Context, role string, permissions []string) error {
	// get role id by string
	roleIDs, err := s.repo.GetRoleIDByName(ctx, []string{role})
	if err != nil {
		return err
	}

	// get permission id by string
	permissionIDs, err := s.repo.GetPermissionIDByName(ctx, permissions)
	if err != nil {
		return err
	}

	// assign permission to role
	err = s.repo.GivePermissionToRole(ctx, roleIDs[0], permissionIDs)
	if err != nil {
		return err
	}
	return nil
}

// AssignUserToRole assigns a user to a role in the system.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - userid: The ID of the user to be assigned to the role.
// - role: The name of the role to which the user will be assigned.
//
// Returns:
// - error: An error if the assignment fails, otherwise nil.
func (s *service) AssignUserToRole(ctx context.Context, userid uint, role string) error {
	// get role id by string
	roleIDs, err := s.repo.GetRoleIDByName(ctx, []string{role})
	if err != nil {
		return err
	}

	// assign permission to role
	err = s.repo.GiveRoleToUser(ctx, userid, roleIDs[0])
	if err != nil {
		return err
	}
	return nil
}

// PolicyACL checks if a user has the permission to perform a specific action.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - userID: The ID of the user.
// - rolePermission: A string representing the role or permission.
// - module: The name of the module. or you can use by path
// - method: The name of the HTTP method.
//
// Returns:
// - bool: True if the user has the permission, false otherwise.
// - error: An error if there was a problem parsing the role or permission, or if there was an error verifying the user's privilege.
//
// note: this function is used inside the middleware
// example rolepermission: "role:admin" or "permission:product.crete" or "role:admin|permission:product.create" or "role:admin,user" or you can use multiple roles and permissions
// example module and method: "GET /api/v1/products"
// example: service.PolicyACL(ctx, 1, "role:admin|permission:product.create", "products", "GET")
// note: you can insert product path as module and then http method GET as method
func (s *service) PolicyACL(ctx context.Context, userID int, rolePermission, module, method string) (bool, error) {
	// Parse the role or permission string
	parsedRolePermission, err := parseRolePermission(rolePermission)
	if err != nil {
		return false, err
	}

	// Verify the user's privilege
	verified, err := s.verifyPrivilege(ctx, userID, parsedRolePermission, module, method)
	if err != nil {
		return false, err
	}

	return verified, nil
}

// VerifyPrivilege checks if a user has the privilege to access a specific module and method.
func (s *service) verifyPrivilege(ctx context.Context, userID int, rolePermission RolePermission, module, method string) (bool, error) {
	module = strings.ToLower(module)
	method = strings.ToLower(method)

	isSuperAdmin, err := s.isSuperAdmin(ctx, uint(userID))
	if err != nil {
		return false, err
	}

	if isSuperAdmin {
		return true, nil
	}

	roleAccess, err := s.CheckRoleAccess(ctx, uint(userID), rolePermission.Roles, module, method)
	if err != nil {
		return false, err
	}

	if roleAccess {
		return true, nil
	}

	permissionAccess, err := s.checkPermissionAccess(ctx, uint(userID), rolePermission.Permissions, module, method)
	if err != nil {
		return false, err
	}

	return permissionAccess, nil
}

// CheckRoleAccess checks if a user has access to a specific role and module method.
func (s *service) CheckRoleAccess(ctx context.Context, userID uint, roles []string, module, method string) (bool, error) {
	if len(roles) == 0 {
		return false, nil
	}

	// Get the role permissions associated with the user's roles
	rolePermissions, err := s.repo.GetAccountHasRolePermissions(ctx, userID, roles)
	if err != nil {
		return false, err
	}

	// Construct the permission name from module and method
	permissionName := module + "." + method

	// Check if the user has the required permission
	for _, permission := range rolePermissions.Permission {
		if permission.Name == permissionName {
			return true, nil
		}
	}

	return false, nil
}

// checkPermissionAccess checks if a user has access to a specific permission for a given module and method.
func (s *service) checkPermissionAccess(ctx context.Context, userID uint, permissions []string, module, method string) (bool, error) {
	if len(permissions) == 0 {
		return false, nil
	}

	// Retrieve the permissions associated with the user's roles and permission list
	accountPermissions, err := s.repo.GetAccountHasPermission(ctx, userID, permissions)
	if err != nil {
		return false, err
	}

	// Construct the permission name from module and method
	permissionName := module + "." + method

	// Check if the user has the required permission
	for _, accountPermission := range accountPermissions {
		if accountPermission.Name == permissionName {
			return true, nil
		}
	}

	return false, nil
}

// Helper function to check if user is Superadmin
func (s *service) isSuperAdmin(ctx context.Context, userid uint) (bool, error) {
	account, err := s.repo.GetAccountRoleByID(ctx, userid)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	return account.RoleName == "Superadmin" || account.RoleName == "Admin", nil
}
