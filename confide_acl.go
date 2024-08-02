package confide_acl

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/cangkir13/confide_acl/repository"
)

type Service struct {
	repo *repository.SQL
}

func NewService(db *sql.DB) *Service {
	return &Service{
		repo: repository.NewSQL(db),
	}
}

type ConfideACL interface {
	SetRole(ctx context.Context, name string) error
	SetPermission(ctx context.Context, name string) error
	AssignPermissionToRole(ctx context.Context, role string, permissions []string) error
	ValidateControl(ctx context.Context, args string) (bool, error)
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
func AuthACL(s *Service, args string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// check permission
			haspr, err := s.ValidateControl(r.Context(), args)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// check if has permission
			if !haspr {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
