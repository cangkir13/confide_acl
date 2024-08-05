package confide_acl

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/cangkir13/confide_acl/repository"
	"github.com/eben-hk/confide"
)

// table default if not set
var defaultTable string = "users"

// config acl service struct
type ConfigACL struct {
	Database     *sql.DB
	TableAccount string
}

type ConfideACL interface {
	AddRole(ctx context.Context, name string) error
	AddPermission(ctx context.Context, name string) error
	AssignPermissionToRole(ctx context.Context, role string, permissions []string) error
	AssignUserToRole(ctx context.Context, userid uint, role string) error
	ValidateControl(ctx context.Context, args string) (bool, error)
}

type service struct {
	repo repository.SQL
}

// NewService creates a new instance of the Service struct.
//
// Parameters:
// - conf: ConfigACL struct containing the database connection and default table account.
//
// Returns:
// - a pointer to the Service struct.
func NewService(conf ConfigACL) service {
	if conf.TableAccount == "" {
		conf.TableAccount = defaultTable
	}
	return service{
		repo: repository.NewSQL(conf.Database, conf.TableAccount),
	}
}

// AuthACL is a middleware function that checks the user's permission before
// allowing them to access the next handler. It takes a Service pointer and a
// string argument, and returns a function that takes a http.Handler and
// returns a http.Handler.
//
// The returned function is an http.HandlerFunc that checks the user's
// permission by calling the ValidateControl method of the Service with the
// request's context and the provided argument. If there is an error in
// validating the control, it returns a BadRequest error. If the user does not
// have the required permission, it returns an Unauthorized error. Otherwise,
// it calls the next handler.
func AuthACL(s *service, args string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// get username id from header
			_, err := extractConsumerID(r.Header.Get("x-consumer-username"))
			if err != nil {
				confide.JSON(w, confide.Payload{
					Code:    confide.FCodeUnauthorized,
					Message: err.Error(),
				})
				return
			}

			// check permission
			haspr, err := s.ValidateControl(r.Context(), args)
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
