package confide_acl

import (
	"context"
)

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
// - error: An error if there was an issue retrieving the role or permission IDs, or if there was an error retrieving the account roles or permissions.
func (s *service) verifyPrivilege(ctx context.Context, userid int, rp RolePermission) (bool, error) {
	var roleaccess, permissionaccess bool = false, false
	var errump []error

	// Get role IDs by name
	if len(rp.Roles) > 0 {
		roleIds, err := s.repo.GetRoleIDByName(ctx, rp.Roles)
		if err != nil {
			return false, err
		}

		if len(roleIds) > 0 {
			hasRoles, err := s.repo.GetAccountRole(ctx, uint(userid), roleIds)
			if err != nil {
				roleaccess = false
				errump = append(errump, err)
			}

			if len(hasRoles) > 0 {
				roleaccess = true
			}
		}
	}
	// Get permission IDs by name
	if len(rp.Permissions) > 0 {
		permissionIds, err := s.repo.GetPermissionIDByName(ctx, rp.Permissions)
		if err != nil {
			return false, err
		}
		if len(permissionIds) > 0 {
			hasPermissions, err := s.repo.GetAccountPermission(ctx, uint(userid), permissionIds)
			if err != nil {
				permissionaccess = false
				errump = append(errump, err)
			}
			if len(hasPermissions) > 0 {
				permissionaccess = true
			}
		}
	}

	if len(errump) > 0 {
		return false, errump[0]
	}

	if !roleaccess && !permissionaccess {
		return false, nil
	}

	// hasaccess
	return true, nil
}
