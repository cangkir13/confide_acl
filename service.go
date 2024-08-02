package confide_acl

import (
	"context"
)

func (s *Service) SetRole(ctx context.Context, name string) error {
	err := s.repo.CreateRole(ctx, name)
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) SetPermission(ctx context.Context, name string) error {
	err := s.repo.CreatePermission(ctx, name)
	if err != nil {
		return err
	}
	return nil
}

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

// ACL checks if a role has the required permissions.
// example args: role:admin|permission:read,write
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
