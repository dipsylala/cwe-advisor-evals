## Verdict

Missing Authorization. The `DeleteProject` RPC method executes without verifying that the caller is authorized to delete the target project. The gRPC server lacks interceptors to enforce authorization, and the method contains no authorization checks of its own.

## Source

Line 36-49: The `DeleteProject` method accepts a project ID and immediately executes a database deletion without verifying the caller's authorization. The method receives no authentication context and performs no ownership or role checks.

Lines 57-69: The `StartServer` function creates a gRPC server with `grpc.NewServer()` using no options—no `grpc.ChainUnaryInterceptor` or other interceptors are registered to enforce authentication or authorization at the server level.

## Fix

1. Add a unary server interceptor to validate authorization for protected methods:

```go
func authorizationInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Extract caller identity from context (e.g., JWT token, mTLS certificate, API key)
	callerID, err := getCallerIdentity(ctx)
	if err != nil || callerID == "" {
		return nil, status.Errorf(codes.Unauthenticated, "caller identity required")
	}
	// Proceed to the handler with the authenticated context
	return handler(ctx, req)
}
```

2. Register the interceptor when creating the server:

```go
grpcServer := grpc.NewServer(
	grpc.ChainUnaryInterceptor(authorizationInterceptor),
)
```

3. Add authorization logic to the `DeleteProject` method to verify the caller owns or administers the project before executing the deletion. Query the database to check if `callerID` has ownership or admin rights on the project, and return `codes.PermissionDenied` if not:

```go
func (s *ProjectServiceServer) DeleteProject(ctx context.Context, req *DeleteProjectRequest) (*DeleteProjectResponse, error) {
	callerID, err := getCallerIdentity(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "caller identity required")
	}

	if req.ProjectId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "project_id is required")
	}

	// Verify the caller owns or administers this project
	authorized, err := s.isAuthorizedToDeleteProject(ctx, callerID, req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "authorization check failed: %v", err)
	}
	if !authorized {
		return nil, status.Errorf(codes.PermissionDenied, "not authorized to delete project")
	}

	_, err = s.DB.ExecContext(ctx, "DELETE FROM projects WHERE id = ?", req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete project %s: %v", req.ProjectId, err)
	}

	log.Printf("project %s deleted by %s", req.ProjectId, callerID)
	return &DeleteProjectResponse{Success: true}, nil
}

func (s *ProjectServiceServer) isAuthorizedToDeleteProject(ctx context.Context, callerID string, projectID string) (bool, error) {
	// Query the database to verify the caller is an owner or admin of the project
	var count int
	err := s.DB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM project_members WHERE project_id = ? AND member_id = ? AND role IN ('owner', 'admin')",
		projectID, callerID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
```

## Explanation

CWE-862 requires that sensitive operations enforce authorization checks. The vulnerability exists at two levels here:

1. **Server level**: The gRPC server is instantiated with no interceptors. Interceptors provide a centralized mechanism to enforce authentication and authorization across all methods, reducing the likelihood of omission in individual handlers.

2. **Method level**: The `DeleteProject` method performs no authorization checks. It accepts any caller and immediately deletes the specified project, allowing unauthorized deletion of any project in the system.

The fix addresses both levels:
- The interceptor extracts and validates the caller's identity, rejecting unauthenticated requests at the server boundary.
- The method verifies the caller has explicit ownership or administrative rights on the target project before executing the deletion.
- Database queries return `codes.PermissionDenied` when the caller lacks authority, distinguishing authorization failures from authentication failures (which return `codes.Unauthenticated`).

This defense-in-depth approach ensures that even if the method-level check is accidentally omitted in the future, the interceptor still protects the endpoint.
