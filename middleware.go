package confide_acl

import (
	"net/http"

	"github.com/eben-hk/confide"
)

// AuthACL is a middleware function that checks the user's permission before
// passing the request to the next handler.
// Parameters:
// - s: A pointer to the Service struct.
// - args: A string representing the role or permission to check. exmple: role:admin or permission:read
// - args: other sample "role:admin|permission:read" or "permission:read,write" or combined both "role:admin|permission:read,write"
// Returns:
// - A function that takes a http.Handler and returns a http.Handler.
func AuthACL(s service, args string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// get username id from header
			userid, err := extractConsumerID(r.Header.Get("x-consumer-username"))
			if err != nil {
				confide.JSON(w, confide.Payload{
					Code:    confide.FCodeUnauthorized,
					Message: err.Error(),
				})
				return
			}

			// parsing string role or permission
			parsing, err := parseRolePermission(args)

			if err != nil {
				confide.JSON(w, confide.Payload{
					Code:    confide.FCodeBadRequest,
					Message: err.Error(),
				})
				return
			}

			// check permission
			haspr, err := s.VerifyPrivilege(r.Context(), userid, parsing)
			if err != nil {
				confide.JSON(w, confide.Payload{
					Code:    confide.FCodeUnauthorized,
					Message: err.Error(),
				})
				return
			}

			// check if has permission
			if !haspr {
				confide.JSON(w, confide.Payload{
					Code:    confide.FCodeUnauthorized,
					Message: "you don't have permission",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
