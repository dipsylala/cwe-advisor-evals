## Verdict
Confirmed. User input flows from HTTP request parameter through the call chain (Case05A → Case05B → Case05C → Case05D) and is concatenated directly into a command string at line 28, enabling OS command injection.

## Source
Case05A.java, line 16: `data = request.getParameter("name");`

The parameter flows untrusted through three pass-through methods (Case05B, Case05C) into the vulnerable sink in Case05D.

## Fix
Replace the string concatenation with an argument array to bypass shell interpretation:

For Windows:
```java
Process process = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", "dir", data});
```

For Unix/Linux:
```java
Process process = Runtime.getRuntime().exec(new String[]{"/bin/ls", data});
```

Alternatively, use ProcessBuilder (modern approach, platform-agnostic):
```java
ProcessBuilder pb;
if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
    pb = new ProcessBuilder("cmd.exe", "/c", "dir", data);
} else {
    pb = new ProcessBuilder("/bin/ls", data);
}
Process process = pb.start();
```

## Explanation
The current code passes a single concatenated string to `Runtime.getRuntime().exec(String)`, which invokes a shell on some platforms and allows shell metacharacters in `data` to break out of the intended argument. By passing arguments as an array (or using ProcessBuilder), each argument is treated as a literal value and shell interpretation is bypassed entirely, preventing injection. The attacker-supplied `data` cannot inject commands or options, only be interpreted as a filename argument to the `dir` or `ls` command.
