package evalcases;


/** Compile-only collaborator the fixture references but does not ship. */
public class AuthenticationException extends Exception {
    private static final long serialVersionUID = 1L;
    public AuthenticationException(String message) { super(message); }
}
