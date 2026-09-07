## Verdict

Exploitable. The DeleteProject RPC method performs an unconditional database DELETE without verifying that the authenticated caller owns the project. Additionally, the gRPC server is initialized without any authentication interceptor, allowing any caller—authenticated or not—to invoke any method.

## Source

The vulnerability originates from two missing authorization checks:

1. **No server-wide authentication interceptor**: Line 63 in `StartServer()` creates the gRPC server with `grpc.NewServer()` and no interceptors, leaving every RPC unprotected.
2. **No resource-level authorization in the handler**: Line 42 in `DeleteProject()` deletes the project based solely on the provided `ProjectId` without verifying the authenticated user owns it.

The untrusted source is the user-supplied `req.ProjectId` from the RPC request. This value flows directly to the database DELETE statement without an ownership check.

## Fix

### File: GrpcMethodNoInterceptorCheck.go

```go
// Package projectserver implements the ProjectService gRPC API used by the
// internal admin console to manage customer projects.
package projectserver

import (
	"context"
	"database/sql"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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

// authInterceptor enforces authentication on all RPC methods.
// It extracts the user ID from the request context and denies
// unauthenticated calls with codes.Unauthenticated.
func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	userID, ok := ctx.Value("user_id").(string)
	if !ok || userID == "" {
		return nil, status.Errorf(codes.Unauthenticated, "user not authenticated")
	}
	return handler(ctx, req)
}

// DeleteProject permanently removes a project. The caller must be
// authenticated and must own the project; otherwise deletion is denied.
func (s *ProjectServiceServer) DeleteProject(ctx context.Context, req *DeleteProjectRequest) (*DeleteProjectResponse, error) {
	if req.ProjectId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "project_id is required")
	}

	// Extract authenticated user from context.
	// The authInterceptor ensures this is present; this check defends against direct handler calls.
	userID, ok := ctx.Value("user_id").(string)
	if !ok || userID == "" {
		return nil, status.Errorf(codes.Unauthenticated, "user not authenticated")
	}

	// Check authorization: verify the caller owns the project.
	// Scoped query: project must exist AND be owned by the authenticated user.
	// If the row is not found, treat it identically to "project not found" to avoid
	// confirming ownership of other projects.
	err := s.DB.QueryRowContext(ctx, "SELECT 1 FROM projects WHERE id = ? AND owner_id = ?", req.ProjectId, userID).Scan(new(interface{}))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, status.Errorf(codes.NotFound, "project not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to verify authorization: %v", err)
	}

	// Authorization check passed; user owns the project. Proceed with deletion.
	_, err = s.DB.ExecContext(ctx, "DELETE FROM projects WHERE id = ?", req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete project %s: %v", req.ProjectId, err)
	}

	log.Printf("project %s deleted by user %s", req.ProjectId, userID)
	return &DeleteProjectResponse{Success: true}, nil
}

// StartServer builds and runs the gRPC server for the project service.
// The server is initialized with authInterceptor to enforce authentication
// on all RPC methods.
func StartServer(db *sql.DB) error {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		return err
	}

	// Register the authentication interceptor via ChainUnaryInterceptor.
	// This ensures every RPC is checked for an authenticated user before the handler runs.
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(authInterceptor),
	)

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
				req := new(DeleteProjectRequest)
				if err := dec(req); err != nil {
					return nil, err
				}
				return srv.(*ProjectServiceServer).DeleteProject(ctx, req)
			},
		},
	},
}
```

## Explanation

The fix adds two layers of authorization to close the CWE-862 vulnerability:

1. **Server-wide authentication interceptor** (new function `authInterceptor`): Registered via `grpc.ChainUnaryInterceptor()` in `StartServer()`, this interceptor runs before every RPC method and extracts the user ID from the request context. If no authenticated user is present, the interceptor denies the call with `codes.Unauthenticated`. This ensures the failure case is centralized and cannot be forgotten on new methods.

2. **Resource-level authorization in DeleteProject**: Before executing the DELETE, the method now verifies that the authenticated user owns the project. It does so with a scoped database query—`WHERE id = ? AND owner_id = ?`—rather than loading by ID first and comparing afterward. This follows the principle that "not found" and "not owned" should be indistinguishable to the caller; a `codes.NotFound` response is returned in both cases, preventing an attacker from enumerating which projects exist.

3. **Logging**: The deletion now logs the user ID, providing an audit trail and helping distinguish legitimate from unauthorized attempts in logs.

The fix adheres to the CWE-862 remediation guidance: it centralizes the authentication check through middleware (preventing accidental omission on new methods), enforces resource-level ownership verification, and fails closed when the user is not authenticated or lacks permission.

## Behaviour changes

- **Line 44–51** (new authInterceptor function): Adds a new gRPC unary interceptor function. This has no direct caller impact; it is registered as middleware and runs transparently before every method.
- **Line 56–57**: Updated DeleteProject docstring to document the authentication and ownership requirements.
- **Line 60–65** (new): Added user authentication check. Returns `codes.Unauthenticated` if the user context is missing. This is a safety measure and should be redundant with the server-level interceptor, but defends against direct handler calls.
- **Line 67–78** (new): Added resource ownership authorization check. Performs a scoped database query and returns `codes.NotFound` if the project does not exist or is not owned by the user. This introduces an additional query to the database before DELETE.
- **Line 80–89**: Existing DELETE logic moved after authorization passes, but the SQL and error handling are otherwise unchanged.
- **Line 90**: Log line now includes the authenticated user ID for audit purposes.
- **Line 107–110** (StartServer change): Registered `authInterceptor` via `grpc.ChainUnaryInterceptor()` when creating the gRPC server. This is a single new argument to `grpc.NewServer()` and does not change the function signature or return value.

**Summary**: The fixes introduce one additional database query per DeleteProject call (the ownership check) and one interceptor invocation per RPC (already part of the gRPC call stack); neither changes the method's return contract or the server's external interface. Callers who are authenticated and own the project will see no difference. Unauthenticated or unauthorized callers will now receive denial errors instead of silent failure or a 200 OK.
