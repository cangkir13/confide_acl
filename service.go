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
func (s *Service) AddRole(ctx context.Context, name string) error {
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
func (s *Service) AddPermission(ctx context.Context, name string) error {
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
func (s *Service) AssignPermissionToRole(ctx context.Context, role string, permissions []string) error {
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

// ValidateControl validates the control by parsing the role or permission string,
// retrieving the corresponding role and permission IDs from the repository,
// and checking if the user has access to the specified role and permission.
// ctx: the context.Context object for handling cancellation and timeouts.
// args: the string representation of the role or permission.
// example: "role:Admin" or "permission:mybo.create"
// or combined "role:Admin|permission:mybo.create"
// or multiple flag "role:Admin|permission:mybo.create,mybo.read"
// Returns a boolean indicating whether the user has access to the specified role and permission,
// and an error if any occurred during the validation process.
func (s *Service) ValidateControl(ctx context.Context, args string) (bool, error) {
	// parsing string role or permission
	rp, err := parseRolePermission(args)

	if err != nil {
		return false, err
	}

	var (
		roleid []uint
		permid []uint
	)

	// get role id by string
	if len(rp.Roles) > 0 {
		roleIds, err := s.repo.GetRoleIDByName(ctx, rp.Roles)
		if err != nil {
			return false, err
		}
		roleid = roleIds
	}

	if len(rp.Permissions) > 0 {
		permissionIds, err := s.repo.GetPermissionIDByName(ctx, rp.Permissions)
		if err != nil {
			return false, err
		}
		permid = permissionIds
	}

	hasaccess, err := s.repo.CheckRolePermission(ctx, roleid, permid)
	if err != nil {
		return false, err
	}

	return hasaccess, nil
}
