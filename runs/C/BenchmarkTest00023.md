## Fix

```java
    private static final long serialVersionUID = 1L;

    // Thread-safe, safe to share across requests. Seeded from OS entropy - do not call setSeed().
    private static final java.security.SecureRandom SECURE_RANDOM = new java.security.SecureRandom();

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = request.getParameter("BenchmarkTest00023");
        if (param == null) param = "";

        // 16 bytes = 128 bits of cryptographic entropy, encoded for safe cookie transport.
        byte[] rememberMeBytes = new byte[16];
        SECURE_RANDOM.nextBytes(rememberMeBytes);
        String rememberMeKey =
                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(rememberMeBytes);

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

        response.getWriter().println("Weak Randomness Test executed");
    }
```

## Explanation

The "remember me" cookie is an authentication credential: anyone who can guess its value is treated as the returning user, so it must be unpredictable. The original code derived it from `new java.util.Random().nextFloat()`, a linear congruential PRNG whose internal state an attacker can recover from observed output, and which in any case yields only about 24 bits of mantissa - the decimal string it produced was both predictable and far too short to resist brute force. The fix replaces that source with a shared `java.security.SecureRandom` instance, which draws its entropy from the operating system and is safe to reuse across threads, and requests a full 16 bytes (128 bits) via `nextBytes` rather than relying on a single float. The buffer is encoded with `Base64.getUrlEncoder().withoutPadding()` so the whole 128 bits survives into the cookie value as transport-safe characters, instead of the earlier trick of trimming `"0."` off a decimal string, which silently discarded entropy. No seed is supplied, since manually seeding a CSPRNG can only reduce the entropy it already draws from the OS.
