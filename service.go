package confide_acl

import (
	"context"
	"database/sql"
	"log"

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

// PolicyACL checks the user's permission to perform an action based on the provided role and permission.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - userid: The ID of the user.
// - args: A string representing the role or permission.
//
// Returns:
// - bool: True if the user has the permission, false otherwise.
// - error: An error if there was a problem parsing the role or permission, or if there was an error verifying the user's privilege.
func (s *service) PolicyACL(ctx context.Context, userid int, args string) (bool, error) {
	// parsing string role or permission
	parsing, err := parseRolePermission(args)

	if err != nil {
		return false, err
	}

	// verify privilege
	verified, err := s.verifyPrivilege(ctx, userid, parsing)
	if err != nil {
		return false, err
	}

	return verified, nil
}

// verifyPrivilege verifies if a user has the required role and permission to access a resource.
//
// Parameters:
// - ctx: The context.Context object for the request.
// - userid: The ID of the user.
// - rp: The RolePermission object containing the roles and permissions to be verified.
//
// Returns:
// - bool: True if the user has the required role and permission, false otherwise.
// - error: An error if there was an issue retrieving the role or permission IDs, or if there was an error retrieving the superadmin status.
func (s *service) verifyPrivilege(ctx context.Context, userid int, rp RolePermission) (bool, error) {
	var errump []error

	// Check if user is Superadmin
	isSuperAdmin, err := s.isSuperAdmin(ctx, uint(userid))
	if err != nil {
		log.Printf("Error checking superadmin status: %v", err)
		return false, err
	}
	if isSuperAdmin {
		return true, nil
	}

	roleaccess, err := s.checkRoleAccess(ctx, uint(userid), rp.Roles)
	if err != nil {
		errump = append(errump, err)
	}

	permissionaccess, err := s.checkPermissionAccess(ctx, uint(userid), rp.Permissions)
	if err != nil {
		errump = append(errump, err)
	}

	if len(errump) > 0 {
		return false, errump[0]
	}

	if !roleaccess && !permissionaccess {
		return false, nil
	}

	return true, nil
}

// Function to check role access
func (s *service) checkRoleAccess(ctx context.Context, userid uint, roles []string) (bool, error) {
	if len(roles) == 0 {
		return false, nil
	}

	roleIDs, err := s.repo.GetRoleIDByName(ctx, roles)
	if err != nil {
		return false, err
	}

	if len(roleIDs) == 0 {
		return false, nil
	}

	hasRoles, err := s.repo.GetAccountRole(ctx, userid, roleIDs)
	if err != nil {
		return false, err
	}

	return len(hasRoles) > 0, nil
}

// Function to check permission access
func (s *service) checkPermissionAccess(ctx context.Context, userid uint, permissions []string) (bool, error) {
	if len(permissions) == 0 {
		return false, nil
	}

	permissionIDs, err := s.repo.GetPermissionIDByName(ctx, permissions)
	if err != nil {
		return false, err
	}

	if len(permissionIDs) == 0 {
		return false, nil
	}

	hasPermissions, err := s.repo.GetAccountPermission(ctx, userid, permissionIDs)
	if err != nil {
		return false, err
	}

	return len(hasPermissions) > 0, nil
}

// Helper function to check if user is Superadmin
func (s *service) isSuperAdmin(ctx context.Context, userid uint) (bool, error) {
	account, err := s.repo.GetAccountRoleByID(ctx, userid)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	return account.RoleName == "Superadmin", nil
}
