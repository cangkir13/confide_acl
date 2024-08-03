package confide_acl

import (
	"errors"
	"strconv"
	"strings"
)

type RolePermission struct {
	Roles       []string
	Permissions []string
}

var (
	ErrUnknownKey           = errors.New("unknown key, valid keys: role, permission")
	ErrInvalidConsumerFomat = errors.New("invalid consumer username format, example: consumer:1")
	ErrInvalidParseFormat   = errors.New("invalid format")
)

// parseRolePermission parses the input string and returns a RolePermission struct and an error.
//
// The input string is expected to be in the format "role:<roles>|permission:<permissions>", where
// <roles> and <permissions> are comma-separated lists of values. The function splits the input
// string by "|" and then by ":", and assigns the values to the corresponding fields in the
// RolePermission struct. If the input string has an invalid format or an unknown key, an error
// is returned.
//
// Parameters:
// - input: the input string to be parsed.
//
// Returns:
// - RolePermission: the parsed RolePermission struct.
// - error: an error if the input string has an invalid format or an unknown key.
func parseRolePermission(input string) (RolePermission, error) {
	var rp RolePermission

	// Split the input string by "|"
	parts := strings.Split(input, "|")
	for _, part := range parts {
		// Split each part by ":"
		keyValue := strings.Split(part, ":")
		if len(keyValue) != 2 {
			return rp, ErrInvalidParseFormat
		}

		key, value := keyValue[0], keyValue[1]
		switch key {
		case "role":
			rp.Roles = strings.Split(value, ",")
		case "permission":
			rp.Permissions = strings.Split(value, ",")
		default:
			return rp, ErrUnknownKey
		}
	}

	return rp, nil
}

// extractConsumerID extracts the consumer ID from the given header value.
//
// Parameters:
// - headerValue: a string representing the header value containing the consumer username.
// example format: "consumer:1"
// Returns:
// - int: the extracted consumer ID.
// - error: an error if the consumer username format is invalid.
func extractConsumerID(headerValue string) (int, error) {
	parts := strings.Split(headerValue, ":")
	if len(parts) != 2 {
		return 0, ErrInvalidConsumerFomat
	}

	return strconv.Atoi(parts[1])
}
