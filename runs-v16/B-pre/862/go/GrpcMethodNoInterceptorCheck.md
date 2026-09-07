## Verdict

CONFIRMED. The gRPC service method `DeleteProject` performs a sensitive operation (permanent database deletion) without any authorization check. The vulnerability spans two locations: (1) the method itself at line 42 has no authorization gate, and (2) the server initialization at line 63 registers no interceptor to enforce authorization centrally.

## Source

**CWE-862: Missing Authorization**

**Location:** `GrpcMethodNoInterceptorCheck.go`, lines 36–49 and 63

**Entry point:** `DeleteProject` method receives a project ID from an unauthenticated caller and deletes it from the database without verifying the caller's identity or permission.

**Root cause:** The gRPC server is created with `grpc.NewServer()` and no `grpc.ChainUnaryInterceptor`, so every RPC method runs with zero authorization enforcement.

## Fix

Add a `grpc.UnaryServerInterceptor` that verifies authentication and authorization before allowing any RPC to execute. Install it when creating the server.

**Step 1: Add the authorization interceptor function (insert before `StartServer`)**

```go
// authorizationInterceptor verifies the caller is authenticated and authorized
// before allowing the RPC to proceed.
func authorizationInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Extract authenticated user ID from context.
	// In a real implementation, this would be populated by an authentication interceptor
	// (e.g., validating a JWT or mTLS certificate), not shown here.
	userID, ok := ctx.Value("userID").(string)
	if !ok || userID == "" {
		return nil, status.Errorf(codes.Unauthenticated, "caller must be authenticated")
	}

	// Verify the caller holds the required role for sensitive operations.
	// DeleteProject requires admin role; tailor this check to your authorization model.
	role, ok := ctx.Value("role").(string)
	if !ok || role != "admin" {
		return nil, status.Errorf(codes.PermissionDenied, "caller does not have permission to perform this operation")
	}

	// Caller is authenticated and authorized; invoke the actual handler.
	return handler(ctx, req)
}
```

**Step 2: Modify `StartServer` to install the interceptor (line 63)**

Change:
```go
	grpcServer := grpc.NewServer()
```

To:
```go
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(authorizationInterceptor),
	)
```

## Explanation

The fix enforces authorization at the gRPC server level using a `grpc.UnaryServerInterceptor`, which is the centralized mechanism Go guidance prescribes for gRPC. The interceptor runs before any RPC method, verifying that the caller is both authenticated (possesses a valid user ID) and authorized (holds the required role). If either check fails, the interceptor returns an error status—`codes.Unauthenticated` if the caller is not logged in, `codes.PermissionDenied` if they lack the required role—before `DeleteProject` or any other method executes.

By installing the interceptor at server creation time via `grpc.ChainUnaryInterceptor`, the check cannot be forgotten on new routes. The interceptor inspects claims stored in the context by an upstream authentication mechanism (e.g., JWT validation or mTLS certificate parsing), so sensitive routes inherit the authorization requirement automatically. This eliminates the gap where an unauthenticated or unauthorized caller could invoke `DeleteProject` directly.

## Behaviour changes

- **Before:** Any caller reaching the gRPC endpoint can delete any project without authentication or authorization checks.
- **After:** Only authenticated callers holding the `"admin"` role can invoke `DeleteProject`. All other requests receive a `PermissionDenied` (or `Unauthenticated` if not logged in) error status without executing the database deletion.
- **Response codes:** The server now returns gRPC status `codes.Unauthenticated` (13) when the caller is not logged in, and `codes.PermissionDenied` (7) when the caller is authenticated but lacks admin role. Previously, all requests received status `codes.OK` (0) regardless.
- **Side effects:** None. The interceptor is installed centrally and applies uniformly to all RPC methods; existing methods continue to function normally when called by authorized users.
