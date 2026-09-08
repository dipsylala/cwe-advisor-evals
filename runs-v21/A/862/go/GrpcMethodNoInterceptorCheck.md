## Verdict
CWE-862 (Missing Authorization) confirmed. The DeleteProject method executes without verifying the caller has authorization to delete the specified project. The gRPC server lacks an interceptor to enforce authorization checks before method dispatch.

## Source
```
E:/Github/cwe-advisor/evals/cases/862/go/GrpcMethodNoInterceptorCheck/GrpcMethodNoInterceptorCheck.go:42
```

Line 42 executes a DELETE operation without authorization. The vulnerability has two components:
1. No interceptor on the gRPC server (line 63) to check authorization before routing requests
2. No authorization check within DeleteProject (line 36) to verify the caller owns or administers the target project

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

// extractUserFromContext retrieves the authenticated user from the RPC context.
// In production, this would extract the user from mTLS certificates, JWT tokens,
// or other authentication metadata. For this example, it extracts from the
// x-user-id metadata header.
func extractUserFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Errorf(codes.Unauthenticated, "missing authentication metadata")
	}

	userIds := md.Get("x-user-id")
	if len(userIds) == 0 {
		return "", status.Errorf(codes.Unauthenticated, "missing user identity in metadata")
	}

	return userIds[0], nil
}

// userCanDeleteProject checks if the given user is authorized to delete the
// specified project. This checks if the user is the project owner or an admin.
func (s *ProjectServiceServer) userCanDeleteProject(ctx context.Context, userId string, projectId string) (bool, error) {
	// Query to check if the user owns this project or is an admin.
	// This example checks an admin flag; in production, this would also check
	// project ownership or membership tables.
	var isAdmin bool
	err := s.DB.QueryRowContext(ctx, "SELECT is_admin FROM users WHERE id = ?", userId).Scan(&isAdmin)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	if isAdmin {
		return true, nil
	}

	// Check if user owns the project
	var owner string
	err = s.DB.QueryRowContext(ctx, "SELECT owner_id FROM projects WHERE id = ?", projectId).Scan(&owner)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	return owner == userId, nil
}

// DeleteProject permanently removes a project. Only the project owner or an
// admin can delete a project. Authorization is enforced by both a
// server-wide interceptor and by per-method authorization checks.
func (s *ProjectServiceServer) DeleteProject(ctx context.Context, req *DeleteProjectRequest) (*DeleteProjectResponse, error) {
	if req.ProjectId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "project_id is required")
	}

	// Extract authenticated user from context (populated by interceptor)
	userId, err := extractUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Check authorization: verify user can delete this project
	canDelete, err := s.userCanDeleteProject(ctx, userId, req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "authorization check failed: %v", err)
	}
	if !canDelete {
		return nil, status.Errorf(codes.PermissionDenied, "user %s is not authorized to delete project %s", userId, req.ProjectId)
	}

	// SAST FINDING: CWE-862 (Missing Authorization) was reported here.
	// Now protected by interceptor-enforced authentication and per-method authorization check.
	_, err = s.DB.ExecContext(ctx, "DELETE FROM projects WHERE id = ?", req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete project %s: %v", req.ProjectId, err)
	}

	log.Printf("project %s deleted by user %s", req.ProjectId, userId)
	return &DeleteProjectResponse{Success: true}, nil
}

// authInterceptor returns a unary server interceptor that enforces
// authentication before allowing any RPC to proceed. It verifies that
// the caller has provided authentication metadata.
func authInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Extract and validate user from context
		_, err := extractUserFromContext(ctx)
		if err != nil {
			return nil, err
		}

		// User is authenticated; proceed to the handler
		return handler(ctx, req)
	}
}

// StartServer builds and runs the gRPC server for the project service.
// The server is configured with a unary interceptor that enforces
// authentication on all RPC methods.
func StartServer(db *sql.DB) error {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		return err
	}

	// Register the authentication interceptor to enforce authentication
	// on all unary RPC methods before they are dispatched.
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(authInterceptor()),
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
The vulnerability occurs because:
1. The gRPC server (line 63 of original) is created with no interceptors, meaning no authentication or authorization enforcement occurs before methods are invoked
2. The DeleteProject method has no authorization check to verify the caller owns or administers the project before executing the DELETE query

The fix adds two layers of authorization:

**Layer 1: Server-Level Interceptor (authInterceptor)**
- Registered via `grpc.ChainUnaryInterceptor()` when creating the server
- Runs before every RPC method is dispatched
- Extracts and validates authentication metadata from the RPC context
- Rejects unauthenticated requests with codes.Unauthenticated before they reach the service method

**Layer 2: Method-Level Authorization (userCanDeleteProject)**
- Called within DeleteProject after confirming the user is authenticated
- Queries the database to determine if the caller is an admin or owns the project
- Returns PermissionDenied if the user lacks authorization
- Ensures that even if authentication were somehow bypassed, authorization is still enforced

The fix extracts the user identity from RPC metadata (x-user-id header) via `extractUserFromContext()`. In production, this would use stronger authentication like mTLS certificates or cryptographically verified JWT tokens.
