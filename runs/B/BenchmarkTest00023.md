## Fix

```java
    private static final long serialVersionUID = 1L;

    // Thread-safe, seeded from OS entropy; safe to share across requests.
    private static final java.security.SecureRandom SECURE_RANDOM = new java.security.SecureRandom();

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = request.getParameter("BenchmarkTest00023");
        if (param == null) param = "";

        byte[] keyBytes = new byte[16]; // 128 bits of entropy for a persistent-login token
        SECURE_RANDOM.nextBytes(keyBytes);
        String rememberMeKey =
                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(keyBytes);

        String user = "Floyd";
        String fullClassName = this.getClass().getName();
        String testCaseNumber =
                fullClassName.substring(
                        fullClassName.lastIndexOf('.') + 1 + "BenchmarkTest".length());
        user += testCaseNumber;

        String cookieName = "rememberMe" + testCaseNumber;

        boolean foundUser = false;
        javax.servlet.http.Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (int i = 0; !foundUser && i < cookies.length; i++) {
                javax.servlet.http.Cookie cookie = cookies[i];
                if (cookieName.equals(cookie.getName())) {
                    if (cookie.getValue().equals(request.getSession().getAttribute(cookieName))) {
                        foundUser = true;
                    }
                }
            }
        }

        if (foundUser) {
            response.getWriter().println("Welcome back: " + user + "<br/>");
        } else {
            javax.servlet.http.Cookie rememberMe =
                    new javax.servlet.http.Cookie(cookieName, rememberMeKey);
            rememberMe.setSecure(true);
            rememberMe.setHttpOnly(true);
            rememberMe.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
            rememberMe.setPath(request.getRequestURI()); // i.e., set path to JUST this servlet
            // e.g., /benchmark/sql-01/BenchmarkTest01001
            request.getSession().setAttribute(cookieName, rememberMeKey);
            response.addCookie(rememberMe);
            response.getWriter()
                    .println(
                            user
                                    + " has been remembered with cookie: "
                                    + rememberMe.getName()
                                    + " whose value is: "
                                    + rememberMe.getValue()
                                    + "<br/>");
        }

        response.getWriter().println("Remember-me token issued");
    }
```

## Explanation

The remember-me cookie value was derived from `new java.util.Random().nextFloat()`, a general-purpose PRNG whose internal 48-bit state can be recovered from observed output, letting an attacker reproduce the sequence and forge another user's persistent-login token; `nextFloat()` also yields only about 24 bits of mantissa, so the token was brute-forceable even without predicting the seed. The value is now drawn from a shared `java.security.SecureRandom` instance, which takes its entropy from the operating system and is not reproducible from prior outputs, and the request is sized to the purpose - 16 bytes, 128 bits, the usual bar for an authentication token - then encoded with `Base64.getUrlEncoder().withoutPadding()` so the full entropy survives transport in a cookie rather than being truncated by string-slicing a floating-point literal. The instance is a `static final` field because `SecureRandom` is thread-safe and reusable, avoiding per-request construction cost, and it is deliberately left unseeded so nothing dilutes the OS entropy pool. The final response line no longer advertises the generator in use.
