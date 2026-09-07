## Verdict

CONFIRMED - Missing Authorization on line 42. The DeleteProject RPC method accepts an attacker-controlled ProjectId and deletes any matching project without checking that the caller owns or has authorization to delete it. The vulnerability is twofold: (1) the gRPC server has no authorization interceptor, and (2) the handler performs no ownership check before the DELETE operation.

## Source

Line 42 in GrpcMethodNoInterceptorCheck.go: `s.DB.ExecContext(ctx, "DELETE FROM projects WHERE id = ?", req.ProjectId)`

The source is the untrusted ProjectId parameter received from the gRPC client request, which flows directly into a DELETE statement without authorization verification.

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

// authorizationInterceptor enforces that all RPC calls are authenticated
// and provides caller identity to handlers via context.
func authorizationInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Extract caller ID from gRPC metadata (set by authentication upstream)
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "missing authentication metadata")
	}

	callerIDs := md.Get("user-id")
	if len(callerIDs) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "missing user-id in metadata")
	}

	callerID := callerIDs[0]
	if callerID == "" {
		return nil, status.Errorf(codes.Unauthenticated, "empty user-id")
	}

	// Store caller ID in context for handler use
	ctx = context.WithValue(ctx, "user_id", callerID)
	return handler(ctx, req)
}

// DeleteProject permanently removes a project that the caller owns.
// The caller's ownership is verified by scoping the DELETE to the caller's user ID.
func (s *ProjectServiceServer) DeleteProject(ctx context.Context, req *DeleteProjectRequest) (*DeleteProjectResponse, error) {
	if req.ProjectId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "project_id is required")
	}

	// Extract caller ID from context (set by authorizationInterceptor)
	callerID, ok := ctx.Value("user_id").(string)
	if !ok || callerID == "" {
		return nil, status.Errorf(codes.Unauthenticated, "no authenticated user")
	}

	// Delete only if the project exists AND is owned by the caller.
	// This scoped query prevents unauthorized deletion of projects owned by other users.
	result, err := s.DB.ExecContext(ctx, "DELETE FROM projects WHERE id = ? AND owner_id = ?", req.ProjectId, callerID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete project %s: %v", req.ProjectId, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to verify deletion: %v", err)
	}

	// If no rows were affected, either the project does not exist or it is not owned by the caller.
	// Return NotFound for both cases to avoid leaking information about project existence.
	if rowsAffected == 0 {
		return nil, status.Errorf(codes.NotFound, "project not found or not owned by caller")
	}

	log.Printf("project %s deleted", req.ProjectId)
	return &DeleteProjectResponse{Success: true}, nil
}

// StartServer builds and runs the gRPC server for the project service.
//
// grpc.NewServer() is now called with grpc.ChainUnaryInterceptor to enforce
// authentication and pass caller identity to handlers.
func StartServer(db *sql.DB) error {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(authorizationInterceptor),
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

The fix adds two layers of authorization enforcement per CWE-862 guidance:

1. **Authentication Interceptor**: A `grpc.UnaryServerInterceptor` installed via `grpc.ChainUnaryInterceptor` extracts the caller's user ID from gRPC metadata headers. This ensures every RPC call is authenticated and provides the caller's identity to handlers. If caller identity is missing or invalid, the interceptor returns `codes.Unauthenticated` before the handler runs.

2. **Ownership-Scoped Query**: The DELETE statement now includes an `AND owner_id = ?` clause that restricts deletion to projects owned by the authenticated caller. If the scoped query affects 0 rows (either the project does not exist or is not owned by the caller), the handler returns `codes.NotFound`. This prevents enumeration attacks that would leak information via different response codes for "project doesn't exist" vs. "project exists but you don't own it."

The imported `google.golang.org/grpc/metadata` package provides `FromIncomingContext()` to read caller identity from gRPC request metadata.

**Assumptions**: The projects table has an `owner_id` column. Caller identity is passed via gRPC metadata header `user-id` by upstream authentication middleware (not shown in this scope).

## Behaviour changes

- **Authentication required**: All RPC calls now require a `user-id` metadata header. Requests without it are rejected with `Unauthenticated`.
- **Ownership enforcement**: DeleteProject now only deletes projects owned by the authenticated caller; attempts to delete projects owned by others return `NotFound`.
- **Return codes**: The method now returns `Unauthenticated` for missing credentials and `NotFound` when ownership verification fails, instead of silently deleting any matching project.
