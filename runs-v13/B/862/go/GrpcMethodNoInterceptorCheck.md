## Verdict

**VULNERABLE**: The `DeleteProject` gRPC method (line 36-49) performs a sensitive operation—permanently deleting a project—without verifying that the caller is authorized to do so. The gRPC server is created without any authorization interceptor (line 63), and the method itself contains no authorization check before executing the database delete (line 42). Any authenticated or unauthenticated caller can invoke this method for any project ID.

## Source

**Location**: `evals/cases/862/go/GrpcMethodNoInterceptorCheck/GrpcMethodNoInterceptorCheck.go`, line 42

**Call chain**: 
- `StartServer()` (line 57) creates a gRPC server with `grpc.NewServer()` and no interceptors
- `RegisterProjectServiceServer()` (line 74) registers the service handler
- `DeleteProject()` method (line 36) is called by the gRPC framework without any authorization middleware
- Line 42 executes the delete without checking the caller's permissions or resource ownership

**Data flow**: Request → Handler → Database delete. The request ProjectId parameter flows directly to the SQL query without authorization validation at any step.

## Fix

**Option 1: Add a server-level authorization interceptor (primary fix)**

```go
// authInterceptor is a gRPC UnaryServerInterceptor that denies all calls.
// Replace this with real authorization logic that extracts the user from context
// and checks role/permission/ownership.
func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Extract authenticated user from context.
	// This example assumes a context value "user" is set by upstream auth.
	user, ok := ctx.Value("user").(string)
	if !ok || user == "" {
		return nil, status.Errorf(codes.Unauthenticated, "user not authenticated")
	}

	// Check authorization for the method.
	// For DeleteProject, verify the user has admin role or owns the project.
	// This is a placeholder; real logic checks role/permission/ownership.
	role, ok := ctx.Value("role").(string)
	if !ok || role != "admin" {
		return nil, status.Errorf(codes.PermissionDenied, "user does not have permission to access this method")
	}

	return handler(ctx, req)
}

// StartServer builds and runs the gRPC server with authorization enforcement.
func StartServer(db *sql.DB) error {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(authInterceptor),
	)

	RegisterProjectServiceServer(grpcServer, &ProjectServiceServer{DB: db})

	log.Println("ProjectService gRPC server listening on :50051")
	return grpcServer.Serve(lis)
}
```

**Option 2: Add resource-level ownership check in the method**

Even with a server-level interceptor, add a resource-ownership check to the query itself to prevent a caller with the required role from deleting another user's or tenant's project:

```go
// DeleteProject permanently removes a project, after verifying the caller
// owns or administers it.
func (s *ProjectServiceServer) DeleteProject(ctx context.Context, req *DeleteProjectRequest) (*DeleteProjectResponse, error) {
	if req.ProjectId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "project_id is required")
	}

	// Extract the authenticated user from context.
	// Assumes upstream auth middleware sets a context value for the user/tenant.
	userId, ok := ctx.Value("userId").(string)
	if !ok || userId == "" {
		return nil, status.Errorf(codes.Unauthenticated, "user not authenticated")
	}

	// Delete the project only if the caller owns it.
	// Scoping the query ensures a no-rows result if the project does not exist
	// or does not belong to the caller.
	result, err := s.DB.ExecContext(ctx, 
		"DELETE FROM projects WHERE id = ? AND owner_id = ?", 
		req.ProjectId, userId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete project %s: %v", req.ProjectId, err)
	}

	// Check if any rows were deleted. If not, the project either does not exist
	// or belongs to someone else; treat both cases identically.
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check deletion result: %v", err)
	}
	if rowsAffected == 0 {
		return nil, status.Errorf(codes.NotFound, "project not found or not owned by caller")
	}

	log.Printf("project %s deleted by user %s", req.ProjectId, userId)
	return &DeleteProjectResponse{Success: true}, nil
}
```

## Explanation

The vulnerability exists at two levels:

1. **Server-level (line 63)**: The gRPC server is created with no interceptor, so all RPC methods run without any authorization middleware. The fix adds `grpc.ChainUnaryInterceptor(authInterceptor)` to enforce authorization on every call before the method body executes.

2. **Method-level (line 42)**: The `DeleteProject` method performs a sensitive action—deleting a project—without checking whether the caller owns or has permission to delete that project. The fix adds:
   - Explicit extraction of the authenticated user from context
   - A check that verifies the caller is authenticated
   - Scoping the DELETE query with `WHERE owner_id = ?` so only the owning user's projects can be deleted
   - Checking `RowsAffected()` to distinguish "project does not exist" from "project exists but you don't own it"; both return 404 (NotFound) to avoid leaking ownership via status code

The combination closes the authorization gap: the interceptor gates access to the method, and the ownership check ensures the caller can only act on their own resources.

## Behaviour changes

- **Authentication enforcement**: The server now requires every RPC caller to be authenticated (verified via context). Unauthenticated requests receive `codes.Unauthenticated`.
- **Authorization enforcement**: After authentication, the server checks whether the caller has the required permission (e.g., admin role). Callers lacking permission receive `codes.PermissionDenied`.
- **Resource-level access control**: Even if a caller has the admin role, they can only delete projects they own. An attempt to delete another user's project returns `codes.NotFound` (404), matching the response for a non-existent project.
- **No silent failures**: If the authorization interceptor or ownership check fails, the delete is denied immediately. There is no silent allow-by-default path.
- **Auditability**: The log message now includes the user ID, making it possible to audit who deleted what.
