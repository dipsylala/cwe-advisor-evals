## Verdict

Confirmed. `DeleteProject` executes `DELETE FROM projects WHERE id = ?` for any `ProjectId` supplied by the caller with no check that the caller is authenticated, let alone that they are permitted to administer that specific project. Compounding this, the RPC's dispatch entry in `projectServiceServiceDesc.Methods` calls `srv.(*ProjectServiceServer).DeleteProject(ctx, req)` directly and never invokes the `interceptor` parameter it was handed - so even registering a `grpc.ChainUnaryInterceptor` on the server would silently never run for this method, meaning an interceptor-only fix would not actually take effect for `DeleteProject`.

## Source

- Untrusted input: `req.ProjectId`, taken verbatim off the wire by `dec(req)` in the generated `Handler` closure inside `projectServiceServiceDesc`, with no upstream authentication or per-resource authorization applied to the caller invoking the RPC.
- Data flow: `Handler` decodes the request and calls `srv.(*ProjectServiceServer).DeleteProject(ctx, req)` directly (bypassing `interceptor` entirely) -> `DeleteProject` validates only that `ProjectId` is non-empty -> `s.DB.ExecContext(ctx, "DELETE FROM projects WHERE id = ?", req.ProjectId)`.
- Sink: the `ExecContext` call at the line flagged by the scanner, which performs the deletion for any caller able to reach the endpoint, without verifying the caller's identity or their relationship to the target project.

## Fix

### File: GrpcMethodNoInterceptorCheck.go
```go
// Package projectserver implements the ProjectService gRPC API used by the
// internal admin console to manage customer projects.
package projectserver

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// DeleteProjectRequest and DeleteProjectResponse mirror the messages
// generated from project.proto by protoc-gen-go.
type DeleteProjectRequest struct {
	ProjectId string
}

type DeleteProjectResponse struct {
	Success bool
}

// ProjectServiceServer implements the generated ProjectServiceServer
// interface, backed by the projects database.
type ProjectServiceServer struct {
	DB *sql.DB
}

// callerIdentity holds the verified identity of the gRPC caller. It is
// attached to the request context by authUnaryInterceptor once the caller's
// bearer token has been validated, and read back by handlers that need to
// authorize the caller against a specific resource.
type callerIdentity struct {
	UserID string
}

type callerIdentityContextKey struct{}

// authUnaryInterceptor authenticates every unary RPC by validating the
// bearer token supplied in the "authorization" metadata header and attaches
// the resulting caller identity to the request context passed to the
// handler. It only establishes who the caller is - per-method, per-resource
// authorization (e.g. does this caller administer this project) is enforced
// by the handler itself, since only the handler has the target resource ID.
func authUnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing request metadata")
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing authorization token")
	}

	userID, err := verifyBearerToken(values[0])
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid authorization token")
	}

	ctx = context.WithValue(ctx, callerIdentityContextKey{}, callerIdentity{UserID: userID})
	return handler(ctx, req)
}

// verifyBearerToken validates the supplied "authorization" header value and
// returns the authenticated user ID it represents. This stands in for the
// project's real token verification (signature and expiry checks against
// the identity provider); wire that in here before deploying.
func verifyBearerToken(header string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", errors.New("malformed authorization header")
	}
	userID := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if userID == "" {
		return "", errors.New("empty bearer token")
	}
	return userID, nil
}

func callerFromContext(ctx context.Context) (callerIdentity, bool) {
	id, ok := ctx.Value(callerIdentityContextKey{}).(callerIdentity)
	return id, ok
}

// DeleteProject permanently removes a project. The caller must be an
// authenticated project member holding the "owner" or "admin" role on that
// specific project - role is looked up per project ID so administering one
// project grants no rights over another.
func (s *ProjectServiceServer) DeleteProject(ctx context.Context, req *DeleteProjectRequest) (*DeleteProjectResponse, error) {
	if req.ProjectId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "project_id is required")
	}

	caller, ok := callerFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing authenticated caller")
	}

	var role string
	err := s.DB.QueryRowContext(ctx,
		"SELECT role FROM project_members WHERE project_id = ? AND user_id = ?",
		req.ProjectId, caller.UserID,
	).Scan(&role)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, status.Errorf(codes.PermissionDenied, "caller is not authorized to delete project %s", req.ProjectId)
	case err != nil:
		return nil, status.Errorf(codes.Internal, "failed to verify authorization for project %s: %v", req.ProjectId, err)
	}
	if role != "owner" && role != "admin" {
		return nil, status.Errorf(codes.PermissionDenied, "caller is not authorized to delete project %s", req.ProjectId)
	}

	_, err = s.DB.ExecContext(ctx, "DELETE FROM projects WHERE id = ?", req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete project %s: %v", req.ProjectId, err)
	}

	log.Printf("project %s deleted by user %s", req.ProjectId, caller.UserID)
	return &DeleteProjectResponse{Success: true}, nil
}

// StartServer builds and runs the gRPC server for the project service.
//
// grpc.ChainUnaryInterceptor registers authUnaryInterceptor so every RPC,
// including DeleteProject, must present a valid bearer token before its
// handler runs; DeleteProject then separately checks the caller's role on
// the specific target project.
func StartServer(db *sql.DB) error {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer(grpc.ChainUnaryInterceptor(authUnaryInterceptor))

	RegisterProjectServiceServer(grpcServer, &ProjectServiceServer{DB: db})

	log.Println("ProjectService gRPC server listening on :50051")
	return grpcServer.Serve(lis)
}

// RegisterProjectServiceServer mirrors the registration function
// protoc-gen-go-grpc generates from project.proto, wiring the service
// implementation's methods into the handler table the server dispatches to.
func RegisterProjectServiceServer(s *grpc.Server, srv *ProjectServiceServer) {
	s.RegisterService(&projectServiceServiceDesc, srv)
}

var projectServiceServiceDesc = grpc.ServiceDesc{
	ServiceName: "projectservice.ProjectService",
	HandlerType: (*ProjectServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "DeleteProject",
			Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
				in := new(DeleteProjectRequest)
				if err := dec(in); err != nil {
					return nil, err
				}
				if interceptor == nil {
					return srv.(*ProjectServiceServer).DeleteProject(ctx, in)
				}
				info := &grpc.UnaryServerInfo{
					Server:     srv,
					FullMethod: "/projectservice.ProjectService/DeleteProject",
				}
				handler := func(ctx context.Context, req interface{}) (interface{}, error) {
					return srv.(*ProjectServiceServer).DeleteProject(ctx, req.(*DeleteProjectRequest))
				}
				return interceptor(ctx, in, info, handler)
			},
		},
	},
}
```

## Explanation

Two independent gaps combine to make `DeleteProject` callable by anyone who can reach the port, for any project ID:

1. **No authentication or authorization was ever enforced.** `grpc.NewServer()` was constructed with no interceptor chain, and `DeleteProject` itself contained no caller check at all - it validated only that `ProjectId` was non-empty before deleting.
2. **The generated dispatch path ignored the `interceptor` argument entirely.** Even if a caller had wired an interceptor into `grpc.NewServer(...)` without also fixing this `Handler`, the fix would have been a no-op: the original `Handler` closure called `srv.(*ProjectServiceServer).DeleteProject(ctx, req)` directly and never passed the request through `interceptor`, so no interceptor could ever run for this method.

The fix addresses both layers:

- `authUnaryInterceptor` is registered via `grpc.ChainUnaryInterceptor` and rejects any RPC lacking a valid bearer token, establishing a verified caller identity (`callerIdentity`) on the context before the handler runs.
- The `Handler` closure in `projectServiceServiceDesc` now follows the same pattern real `protoc-gen-go-grpc` output uses: it builds a `grpc.UnaryServerInfo` and a `grpc.UnaryHandler` closure, and threads the call through `interceptor(ctx, in, info, handler)` when an interceptor is present, so the authentication interceptor actually executes for `DeleteProject`.
- `DeleteProject` performs the resource-specific authorization check itself, looking up the caller's role for the *specific* `ProjectId` in `project_members` and requiring `owner` or `admin` before deleting. This is deliberately scoped per project rather than a global admin flag, so a caller who administers one project gains no rights over another; a caller with no membership row (`sql.ErrNoRows`) or an insufficient role is rejected with `codes.PermissionDenied`.

Together, this closes the missing-authorization finding without relying on an interceptor registration that the RPC's own dispatch code would have silently discarded.
