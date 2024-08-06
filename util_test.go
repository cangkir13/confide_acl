package confide_acl

import "testing"

// Unit test for parseRolePermission
func TestParseRolePermission(t *testing.T) {
	tests := []struct {
		input          string
		expectedOutput RolePermission
		expectedError  bool
	}{
		{
			input: "role:admin|permission:read,write",
			expectedOutput: RolePermission{
				Roles:       []string{"admin"},
				Permissions: []string{"read", "write"},
			},
			expectedError: false,
		},
		{
			input: "role:user|permission:view",
			expectedOutput: RolePermission{
				Roles:       []string{"user"},
				Permissions: []string{"view"},
			},
			expectedError: false,
		},
		{
			input: "role:guest",
			expectedOutput: RolePermission{
				Roles:       []string{"guest"},
				Permissions: nil,
			},
			expectedError: false,
		},
		{
			input: "permission:execute",
			expectedOutput: RolePermission{
				Roles:       nil,
				Permissions: []string{"execute"},
			},
			expectedError: false,
		},
		{
			input:          "invalid_format",
			expectedOutput: RolePermission{},
			expectedError:  true,
		},
		{
			input:          "unknownkey:value",
			expectedOutput: RolePermission{},
			expectedError:  true,
		},
	}

	for _, test := range tests {
		output, err := parseRolePermission(test.input)
		if (err != nil) != test.expectedError {
			t.Errorf("parseRolePermission(%s) returned error: %v, expected error: %v", test.input, err, test.expectedError)
		}
		if !equalRolePermission(output, test.expectedOutput) {
			t.Errorf("parseRolePermission(%s) returned %v, expected %v", test.input, output, test.expectedOutput)
		}
	}
}

// Helper function to compare two RolePermission structs
func equalRolePermission(a, b RolePermission) bool {
	if len(a.Roles) != len(b.Roles) || len(a.Permissions) != len(b.Permissions) {
		return false
	}

	for i := range a.Roles {
		if a.Roles[i] != b.Roles[i] {
			return false
		}
	}

	for i := range a.Permissions {
		if a.Permissions[i] != b.Permissions[i] {
			return false
		}
	}

	return true
}
