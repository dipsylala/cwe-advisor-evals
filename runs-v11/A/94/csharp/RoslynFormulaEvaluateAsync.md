## Verdict

This is a genuine CWE-94 vulnerability. User-supplied expressions are evaluated as arbitrary C# code through `CSharpScript.EvaluateAsync()` without restriction, enabling remote code execution.

## Source

The vulnerability exists in the call chain:
- `FormulaPreviewController.cs` line 19: receives untrusted user input `request.Expression` from an HTTP POST body
- `FormulaEvaluator.cs` line 14: passes `expression` directly to `CSharpScript.EvaluateAsync(expression, options, sample)`

The expression parameter flows unvalidated from user input to code evaluation.

## Fix

Replace Roslyn scripting with a restricted expression evaluator. If formula evaluation is the intended use, adopt a purpose-built math expression library instead:

**Option 1 (Recommended):** Use a math expression evaluator like `NLua`, `Jint`, or a simple expression tree evaluator that supports only mathematical operations.

**Option 2:** If Roslyn must be used, implement strict whitelisting:
- Parse the expression syntax tree using `CSharpSyntaxTree.ParseText()`
- Validate that the tree contains only whitelisted node types (e.g., `InvocationExpression`, `BinaryExpression`, `IdentifierName` for specific identifiers)
- Reject any nodes related to method calls, field access, type instantiation, or control flow outside the whitelist
- Only then evaluate via `CSharpScript.EvaluateAsync()`

**Option 3:** Use expression trees with `Expression.Lambda()` and compile to a delegate, limiting to mathematical operators and parameter references.

Applying Option 1 (example with a hypothetical math library):
- Replace `CSharpScript.EvaluateAsync(expression, options, sample)` with a call to a restricted evaluator that only interprets mathematical expressions
- Validate that `expression` matches a safe pattern (e.g., contains only digits, operators `+`, `-`, `*`, `/`, `%`, parentheses, and known variable names)
- Return a numeric result instead of arbitrary object results

## Explanation

CWE-94 covers improper control over code generation and evaluation. Roslyn's `CSharpScript.EvaluateAsync()` executes arbitrary C# code, including method calls, type instantiation, and system operations. An attacker can supply expressions like `System.Diagnostics.Process.Start("cmd.exe")` to execute arbitrary commands on the server.

The fix depends on the actual intent: if only mathematical formulas are needed, a dedicated expression evaluator is safer and simpler. If general scripting is required, the code generator output must be strictly validated against a whitelist before evaluation, rejecting all constructs outside the intended scope.
