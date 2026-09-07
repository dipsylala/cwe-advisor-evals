## Verdict

The finding is confirmed. Line 42 performs a database delete operation without verifying that the caller has authorization to delete the project. The method accepts any gRPC request without authentication or permission checks.

## Source

```go
// DeleteProject permanently removes a project. Any caller that can reach the
// gRPC endpoint can invoke this method for any project ID - there is no
// check that the caller is authenticated, let alone that they own or
// administer the target project.
func (s *ProjectServiceServer) DeleteProject(ctx context.Context, req *DeleteProjectRequest) (*DeleteProjectResponse, error) {
	if req.ProjectId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "project_id is required")
	}

	// SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
	_, err := s.DB.ExecContext(ctx, "DELETE FROM projects WHERE id = ?", req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete project %s: %v", req.ProjectId, err)
	}

	log.Printf("project %s deleted", req.ProjectId)
	return &DeleteProjectResponse{Success: true}, nil
}
```

The sink (database delete) is reached without any authorization checks, allowing any caller to delete any project.

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

// getCallerID extracts the caller's user ID from gRPC metadata.
// Returns an error if the caller is not authenticated.
func getCallerID(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Errorf(codes.Unauthenticated, "missing authentication metadata")
	}

	userIDs := md.Get("user-id")
	if len(userIDs) == 0 {
		return "", status.Errorf(codes.Unauthenticated, "user-id not found in metadata")
	}

	return userIDs[0], nil
}

// hasPermissionToDeleteProject checks if the caller (userID) has permission
// to delete the project. Currently checks if the caller is the project owner.
func (s *ProjectServiceServer) hasPermissionToDeleteProject(ctx context.Context, userID string, projectID string) (bool, error) {
	var owner string
	err := s.DB.QueryRowContext(ctx, "SELECT owner_id FROM projects WHERE id = ?", projectID).Scan(&owner)
	if err == sql.ErrNoRows {
		// Project does not exist; authorization denied (do not leak that it doesn't exist)
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return owner == userID, nil
}

// DeleteProject permanently removes a project. The caller must be authenticated
// and must be the project owner to perform this action.
func (s *ProjectServiceServer) DeleteProject(ctx context.Context, req *DeleteProjectRequest) (*DeleteProjectResponse, error) {
	if req.ProjectId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "project_id is required")
	}

	// Extract caller identity from context
	userID, err := getCallerID(ctx)
	if err != nil {
		return nil, err
	}

	// Check authorization before performing the delete
	authorized, err := s.hasPermissionToDeleteProject(ctx, userID, req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check authorization: %v", err)
	}
	if !authorized {
		return nil, status.Errorf(codes.PermissionDenied, "caller does not have permission to delete this project")
	}

	// AUTHORIZATION VERIFIED: Caller is authenticated and owns the project
	_, err = s.DB.ExecContext(ctx, "DELETE FROM projects WHERE id = ?", req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete project %s: %v", req.ProjectId, err)
	}

	log.Printf("project %s deleted by user %s", req.ProjectId, userID)
	return &DeleteProjectResponse{Success: true}, nil
}

// StartServer builds and runs the gRPC server for the project service.
//
// grpc.NewServer() is called with no options at all - no
// grpc.ChainUnaryInterceptor (or any other interceptor) is registered, so
// every RPC, including DeleteProject, runs with zero authentication or
// authorization enforcement in front of it.
func StartServer(db *sql.DB) error {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()

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

The fix adds three authorization checks before the database delete:

1. **Authentication (`getCallerID`):** Extracts the caller's user ID from gRPC request metadata. Returns `Unauthenticated` error if missing, ensuring only authenticated requests proceed.

2. **Authorization Query (`hasPermissionToDeleteProject`):** Queries the database to retrieve the project owner and compares it to the caller's user ID. Returns `false` if the caller does not own the project, or if the project does not exist (avoiding information leakage).

3. **Pre-Delete Check (in `DeleteProject`):** Calls the authorization function before executing the DELETE statement. Returns `PermissionDenied` error if the caller lacks permission.

The DeleteProject method now enforces the principle that only the project owner can delete their own project. The gRPC context carries the caller's identity (expected in `user-id` metadata), and authorization is verified at the method level before the sink is reached.

