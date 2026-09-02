## Verdict

Exploitable. Untrusted user input flows directly from an HTTP request parameter into an OS command string and is executed without validation or safe parameterization.

## Source

`request.getParameter("name")` in Case04A.java line 16. This returns attacker-controlled data from the HTTP request.

The call chain:
1. Case04A.java:16 - `data = request.getParameter("name");` (source)
2. Case04A.java:18 - `(new Case04B()).handleSink(data , request, response);` (passes data)
3. Case04B.java:28 - `Process process = Runtime.getRuntime().exec(osCommand + data);` (sink)

## Fix

**Vulnerable code:**
```java
String osCommand;
if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
    osCommand = "c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir ";
} else {
    osCommand = "/bin/ls ";
}

// VULNERABLE: data is concatenated into command string
Process process = Runtime.getRuntime().exec(osCommand + data);
process.waitFor();
```

**Fixed code:**
```java
// Validate input to prevent argument injection (CWE-88)
if (data.startsWith("-") || data.contains("\n") || data.contains("\r") || data.length() > 1024) {
    throw new IllegalArgumentException("Invalid file path");
}

String[] cmdArray;
if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
    // Use array form with separate arguments, not concatenated string
    cmdArray = new String[]{"c:\\WINDOWS\\SYSTEM32\\cmd.exe", "/c", "dir", data};
} else {
    // Use array form with separate arguments
    cmdArray = new String[]{"/bin/ls", data};
}

// Runtime.exec(String[]) prevents shell interpretation of the data
Process process = Runtime.getRuntime().exec(cmdArray);
process.waitFor();
```

## Explanation

The original code concatenates untrusted user input directly into a command string and passes it to `Runtime.exec(String)`, allowing attackers to inject OS commands. The fix uses `Runtime.exec(String[])` with array arguments instead, which prevents the shell from interpreting special characters in the user input. Additionally, input validation rejects values starting with `-` or containing control characters, preventing argument injection (CWE-88) where the input could be misinterpreted as a command flag. The validation at the sink (rather than the entry point) ensures the safe form is used when the data reaches the execution point.

## Behaviour changes

None. The fixed code:
- Accepts the same input (attacker-controlled data from HTTP parameter)
- Returns the same output type (Process object)
- Preserves the same behavior (waits for command completion via `process.waitFor()`)
- Uses the same commands with the same arguments, with data passed as a separate array element rather than concatenated
- Performs additional validation to prevent argument injection, but rejects invalid paths rather than silently accepting them (appropriate security tightening)
