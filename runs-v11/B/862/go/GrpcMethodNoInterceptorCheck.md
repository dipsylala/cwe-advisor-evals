## Verdict

Exploitable.

## Source

Untrusted gRPC client request. Any caller can invoke `DeleteProject` without authentication or authorization. The gRPC service is initialized with `grpc.NewServer()` and no interceptor chain, permitting unauthenticated method calls to reach the handler.

## Fix

**Vulnerable code (lines 36–49, 57–69):**

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
```

**Fixed code:**

```go
// authInterceptor enforces authentication on all gRPC methods.
// In production, this would validate JWT tokens, mTLS certificates, or other credentials
// and extract the authenticated caller's identity into context.
func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Check for authenticated caller in context (e.g., from JWT middleware or mTLS).
	// For this example, we assume a middleware earlier in the chain has set "user_id".
	userID, ok := ctx.Value("user_id").(string)
	if !ok || userID == "" {
		return nil, status.Errorf(codes.Unauthenticated, "authentication required")
	}
	// Continue to the actual handler now that the caller is authenticated.
	return handler(ctx, req)
}

// DeleteProject permanently removes a project only if the caller owns it.
// The caller is authenticated via the interceptor, and authorization is enforced
// by scoping the query to the authenticated user's projects.
func (s *ProjectServiceServer) DeleteProject(ctx context.Context, req *DeleteProjectRequest) (*DeleteProjectResponse, error) {
	if req.ProjectId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "project_id is required")
	}

	// Extract the authenticated caller from context (set by authInterceptor).
	userID, ok := ctx.Value("user_id").(string)
	if !ok || userID == "" {
		return nil, status.Errorf(codes.Unauthenticated, "authentication required")
	}

	// Scope the deletion to projects the caller owns. If the project doesn't exist
	// or is owned by someone else, RowsAffected will be 0.
	result, err := s.DB.ExecContext(ctx, "DELETE FROM projects WHERE id = ? AND owner_id = ?", req.ProjectId, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete project %s: %v", req.ProjectId, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to verify deletion: %v", err)
	}
	if rowsAffected == 0 {
		// Return 404 for both "not found" and "not owned" to avoid enumeration.
		return nil, status.Errorf(codes.NotFound, "project not found")
	}

	log.Printf("project %s deleted by user %s", req.ProjectId, userID)
	return &DeleteProjectResponse{Success: true}, nil
}

// StartServer builds and runs the gRPC server with authentication/authorization enforced.
func StartServer(db *sql.DB) error {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		return err
	}

	// Install the authInterceptor via ChainUnaryInterceptor to enforce authentication
	// on all unary RPC methods before they reach the handler.
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(authInterceptor),
	)

	RegisterProjectServiceServer(grpcServer, &ProjectServiceServer{DB: db})

	log.Println("ProjectService gRPC server listening on :50051")
	return grpcServer.Serve(lis)
}
```

## Explanation

The original code allows any caller to invoke `DeleteProject` without any authentication or authorization. The gRPC server is created with no interceptor chain, permitting unauthenticated requests to proceed directly to the handler. Even though the handler validates the `ProjectId` is not empty, it does not verify the caller is authenticated or owns the project—the `ProjectId` flows directly into the database DELETE query.

The fix adds a two-part authorization layer. First, an `authInterceptor` installed via `grpc.ChainUnaryInterceptor()` in `StartServer()` enforces authentication at the server level; any RPC without valid authentication is denied with `codes.Unauthenticated` before reaching the handler. Second, `DeleteProject` extracts the authenticated caller's user ID from context and adds an ownership check to the SQL query: `DELETE FROM projects WHERE id = ? AND owner_id = ?`. If the project does not exist or is not owned by the authenticated caller, the query affects zero rows, and the handler returns `codes.NotFound` for both cases to prevent enumeration attacks. This scoped-query pattern is the standard Go defence against resource-level authorization bypass and ensures that even an authenticated attacker cannot delete another user's project.

## Behaviour changes

- **New interceptor function `authInterceptor` added:** Validates authentication before any RPC method executes. Denies unauthenticated calls with `status.Errorf(codes.Unauthenticated, ...)`.
- **DeleteProject now extracts `user_id` from context:** Required by the new ownership check; this extraction assumes a prior middleware or interceptor (e.g., JWT validation) has populated context with the caller's identity.
- **SQL query now includes ownership clause:** Changed from `DELETE FROM projects WHERE id = ?` to `DELETE FROM projects WHERE id = ? AND owner_id = ?`. This prevents deletion of projects not owned by the caller.
- **Check result of `RowsAffected()`:** The fixed code calls `result.RowsAffected()` to confirm whether any rows were deleted. If zero rows were affected, the handler returns `codes.NotFound` rather than a success response. The original code ignored this and always returned success. This behaviour change is necessary to enforce the authorization check and inform the caller whether the deletion succeeded.
- **gRPC server initialization now passes interceptor option:** `grpc.NewServer()` now receives `grpc.ChainUnaryInterceptor(authInterceptor)` to enforce authentication on all unary methods. The original passed no options.

The query's WHERE clause now defines authorization rather than an inline check, following the Go language guidance: "scope the query by the authenticated user's ID rather than loading by primary key and comparing afterwards."
