package evalcases;


/** Compile-only collaborator the fixture references but does not ship. */
public interface Authenticator {
    void authenticate(String username, String password) throws AuthenticationException;
}
