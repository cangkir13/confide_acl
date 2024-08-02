package confide_acl

import (
	"fmt"
	"strings"
)

type RolePermission struct {
	Roles       []string
	Permissions []string
}

func parseRolePermission(input string) (RolePermission, error) {
	var rp RolePermission

	// Split the input string by "|"
	parts := strings.Split(input, "|")
	for _, part := range parts {
		// Split each part by ":"
		keyValue := strings.Split(part, ":")
		if len(keyValue) != 2 {
			return rp, fmt.Errorf("invalid format: %s", part)
		}

		key, value := keyValue[0], keyValue[1]
		switch key {
		case "role":
			rp.Roles = strings.Split(value, ",")
		case "permission":
			rp.Permissions = strings.Split(value, ",")
		default:
			return rp, fmt.Errorf("unknown key: %s", key)
		}
	}

	return rp, nil
}
