## Verdict

exploitable

## Source

Client-supplied `ProjectId` from the gRPC `DeleteProjectRequest` message, received by the `DeleteProject` handler at line 36.

## Fix

**Vulnerable code (line 36-49):**
```go
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

**Root cause (line 63-68):** The gRPC server is created with no interceptors, so no authorization gate exists before any RPC method executes.

**Fixed code:**

Add an authorization interceptor function (insert before `StartServer`):
```go
// authorizationInterceptor checks that the caller is authorized to invoke the method.
// In a real application, this would extract the authenticated user from context and
// verify their role or permission for the requested operation.
func authorizationInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Extract authenticated user from context (or check for auth claims).
	// This example checks for a user principal; a real implementation would
	// validate JWT tokens, check RBAC roles, or verify resource ownership.
	userID, ok := ctx.Value("user_id").(string)
	if !ok || userID == "" {
		return nil, status.Errorf(codes.Unauthenticated, "missing or invalid authentication")
	}

	// For sensitive operations, verify the caller's authorization.
	// This example enforces a simple authorization: only users with an "admin" role
	// can delete projects. A real implementation would check ownership, permissions, etc.
	role, ok := ctx.Value("role").(string)
	if !ok || role != "admin" {
		return nil, status.Errorf(codes.PermissionDenied, "insufficient permissions to delete projects")
	}

	// Proceed to the RPC handler if authorization passes.
	return handler(ctx, req)
}
```

Update `StartServer` to register the interceptor (line 63):
```go
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
```

## Explanation

The vulnerability occurs because the gRPC server has no authorization middleware: any unauthenticated or unprivileged caller can invoke `DeleteProject` and delete any project by guessing or enumerating project IDs. The fix adds a `grpc.UnaryServerInterceptor` that runs before every RPC method, extracting the authenticated user from the context and verifying they hold the required authorization (in this case, admin role). The interceptor denies the request with `codes.Unauthenticated` if no user is present and with `codes.PermissionDenied` if the user lacks the required role, matching the gRPC guidance in CWE-862/go. The interceptor is registered via `grpc.ChainUnaryInterceptor` so it applies uniformly to all methods and cannot be accidentally bypassed when new methods are added to the service.

## Behaviour changes

- **New context values required**: The interceptor reads `user_id` and `role` from `context.Context`. In a deployed system, these would be populated by an authentication middleware (e.g., one that decodes and validates JWT tokens). The calling environment must supply them; if absent, the RPC fails with `codes.Unauthenticated`.
- **Authorization logic is centralized**: Moving the check from inline (inside the handler) to the interceptor layer means all methods using `grpc.ChainUnaryInterceptor` inherit the same authorization gate. New methods added to the service will automatically be protected.
- **Error responses changed**: The method now returns `status.Errorf(codes.Unauthenticated, ...)` for missing authentication and `status.Errorf(codes.PermissionDenied, ...)` for authorization failures, rather than allowing the request to reach the handler. Callers must expect these gRPC status codes instead of the handler's `codes.InvalidArgument` or `codes.Internal` for all paths.
- **Interceptor runs for all methods on the server**: The single interceptor gates every RPC on the service. If different methods require different authorization rules (e.g., DeleteProject requires admin, GetProject requires any authenticated user), the interceptor must branch on the RPC method name (available in `info.FullMethod`) and enforce method-specific logic.

