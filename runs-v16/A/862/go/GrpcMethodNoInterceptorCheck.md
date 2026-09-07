## Verdict

Missing authorization at line 42. The `DeleteProject` method executes a destructive database operation without verifying that the caller is authenticated or that they have permission to delete the target project.

## Source

The vulnerability manifests in two places:

1. **Line 42** (the sink): `s.DB.ExecContext(ctx, "DELETE FROM projects WHERE id = ?", req.ProjectId)` executes without authorization checks.

2. **Line 63** (the missing guard): `grpc.NewServer()` is created with no interceptor middleware. This means every RPC handler, including `DeleteProject`, runs without any authentication or authorization enforcement.

The caller can be unauthenticated, and even if authenticated, there is no check that they own or administer the project they are attempting to delete.

## Fix

Add a `UnaryServerInterceptor` to the gRPC server that extracts and validates caller identity from request metadata, and modify the `DeleteProject` method to enforce authorization:

```go
import (
	"metadata"  // or similar auth package
	"google.golang.org/grpc/metadata"
)

// authUnaryInterceptor validates authentication on every unary RPC.
// It extracts the authorization token from metadata and verifies the caller
// is authenticated. Pass this to grpc.ChainUnaryInterceptor when creating
// the server.
func authUnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
	}
	
	// Extract and validate the authorization token (e.g., JWT).
	// This example checks for a bearer token; adapt to your auth scheme.
	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "missing authorization token")
	}
	
	// Validate the token and extract the user ID.
	userID, err := validateToken(authHeaders[0])
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid authorization token: %v", err)
	}
	
	// Store the authenticated user ID in context for use by handlers.
	ctx = context.WithValue(ctx, "userID", userID)
	return handler(ctx, req)
}

// validateToken parses and validates the authorization token.
// Returns the authenticated user ID on success, or an error.
// Adapt this to your authentication scheme (JWT, session, etc.).
func validateToken(token string) (string, error) {
	// Implement your token validation logic here.
	// For example, parse a JWT, verify the signature, and extract the subject (user ID).
	// This is a placeholder.
	if token == "" {
		return "", fmt.Errorf("empty token")
	}
	// Return the user ID extracted from the token.
	return "user123", nil // replace with actual implementation
}

// DeleteProject now enforces authorization.
func (s *ProjectServiceServer) DeleteProject(ctx context.Context, req *DeleteProjectRequest) (*DeleteProjectResponse, error) {
	if req.ProjectId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "project_id is required")
	}

	// Extract the authenticated user ID from context (set by authUnaryInterceptor).
	userID, ok := ctx.Value("userID").(string)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "user not authenticated")
	}

	// Check that the user owns or administers the project before allowing deletion.
	// Query the database to verify ownership.
	var owner string
	err := s.DB.QueryRowContext(ctx, "SELECT owner FROM projects WHERE id = ?", req.ProjectId).Scan(&owner)
	if err == sql.ErrNoRows {
		return nil, status.Errorf(codes.NotFound, "project not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check project ownership: %v", err)
	}

	// Only the project owner (or an admin) can delete it.
	if owner != userID && !isAdmin(ctx, userID) {
		return nil, status.Errorf(codes.PermissionDenied, "you do not have permission to delete this project")
	}

	// Now safe to delete.
	_, err = s.DB.ExecContext(ctx, "DELETE FROM projects WHERE id = ?", req.ProjectId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete project %s: %v", req.ProjectId, err)
	}

	log.Printf("project %s deleted by user %s", req.ProjectId, userID)
	return &DeleteProjectResponse{Success: true}, nil
}

// isAdmin checks whether the user holds admin privileges.
// Adapt to your authorization model.
func isAdmin(ctx context.Context, userID string) bool {
	// Implement your admin check here.
	// For example, query a users/roles table, check a JWT claim, or consult an ACL.
	return false // placeholder
}

// StartServer now registers the authentication interceptor.
func StartServer(db *sql.DB) error {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		return err
	}

	// Register the authUnaryInterceptor to enforce authentication on all RPC methods.
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(authUnaryInterceptor),
	)

	RegisterProjectServiceServer(grpcServer, &ProjectServiceServer{DB: db})

	log.Println("ProjectService gRPC server listening on :50051")
	return grpcServer.Serve(lis)
}
```

## Explanation

The vulnerability occurs because:

1. **No authentication middleware**: The gRPC server (line 63) is created with no interceptor, so every RPC runs unauthenticated.

2. **No authorization checks**: The `DeleteProject` method (line 36) performs a destructive operation without verifying the caller's identity or permissions.

The fix implements defense-in-depth:

- **Interceptor-level authentication** (`authUnaryInterceptor`): Validates that every inbound RPC includes a valid authorization token in the request metadata, extracted from the `authorization` header. This rejects all unauthenticated calls at the entry point.

- **Method-level authorization** (in `DeleteProject`): Retrieves the authenticated user ID from context (set by the interceptor), queries the database to confirm the user owns the target project (or holds admin privileges), and only then executes the deletion.

- **Token validation** (`validateToken`): Parses and verifies the authorization token (e.g., JWT). Adapt this to your authentication scheme.

- **Ownership check**: Queries the projects table to confirm the caller owns the project before allowing deletion. Users who do not own the project receive a `PermissionDenied` error.

The interceptor enforces authentication on all RPCs in one place, reducing duplication; the method-level check enforces resource-level authorization specific to the `DeleteProject` operation. Together, they prevent unauthorized deletion.
