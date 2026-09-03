## Verdict
The vulnerability is confirmed. Line 50 passes a single string containing unsanitized user input to `Runtime.getRuntime().exec(command)`, enabling OS command injection when the `host` parameter contains shell metacharacters.

## Source
Line 48 concatenates the `host` parameter (from `request.getParameter("host")`) into a command string without validation or escaping:
```
String command = "ping -c " + PING_COUNT + " " + host;
```

Line 50 passes this string to the single-string variant of `Runtime.exec()`:
```
Process process = Runtime.getRuntime().exec(command);
```

When `Runtime.exec(String)` receives a single string, it uses a `StringTokenizer` to split on whitespace. This tokenizer does not parse shell metacharacters (`&`, `;`, `|`, `>`, `$()`, etc.), so an attacker can inject commands by including them in the `host` parameter. For example, `host=example.com; rm -rf /` would be tokenized as separate arguments, allowing the shell to interpret the injected command.

## Fix
Replace the single-string `exec()` call with the array variant, passing each argument as a separate element. This ensures shell metacharacters in user input are treated as literal characters, not shell syntax:

```java
private String runPing(String host) throws IOException, InterruptedException {
    String[] command = {"ping", "-c", String.valueOf(PING_COUNT), host};
    Process process = Runtime.getRuntime().exec(command);

    StringBuilder result = new StringBuilder();
    try (BufferedReader reader =
            new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        String line;
        while ((line = reader.readLine()) != null) {
            result.append(line).append(System.lineSeparator());
        }
    }
    process.waitFor();
    return result.toString();
}
```

The array form passes arguments directly to the OS without shell interpretation, eliminating the injection vector.

## Explanation
`Runtime.exec(String)` is unsafe for command construction with dynamic input because it relies on `StringTokenizer` to split the string, which does not handle shell syntax. The array form, `Runtime.exec(String[])`, bypasses the shell entirely and passes arguments directly to the OS, making shell injection impossible.

For defense-in-depth, consider restricting the `host` parameter to a hostname allowlist or validating it against a pattern (e.g., alphanumeric, dots, hyphens only) before use, even though the array form alone eliminates the injection risk.
