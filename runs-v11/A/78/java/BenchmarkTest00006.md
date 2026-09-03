## Verdict
Real - OS command injection through shell metacharacter injection in ProcessBuilder argument.

## Source
Line 62: `argList.add("echo " + param);` where `param` is attacker-controlled request header data.

The vulnerability occurs because user input is concatenated into a string that becomes the command passed to `sh -c` or `cmd.exe /c`. When ProcessBuilder executes the command with a shell interpreter, shell metacharacters in the concatenated input are interpreted (`;`, `|`, `&`, backticks, `$()`, etc.), allowing arbitrary command execution.

## Fix
Replace line 62:
```
argList.add("echo " + param);
```

With:
```
argList.add("echo");
argList.add(param);
```

## Explanation
ProcessBuilder with an argument list prevents shell metacharacter injection by treating each argument as a distinct token that the OS passes to the target program as separate parameters, not as a shell command line to be parsed.

By passing `"echo"` and the user input as separate arguments, the user input becomes a literal argument value to the `echo` command rather than part of a shell command string. The shell never parses it for metacharacters—it simply receives it as-is and passes it to `echo`.

This fix converts the vulnerable pattern (building a command string with concatenated user input, then passing it to a shell via `-c`) into the safe pattern (passing user data as separate arguments that bypass shell parsing entirely).
