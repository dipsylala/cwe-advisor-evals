## Verdict

Exploitable. User input from the HTTP request body is passed directly to SpEL's `parseExpression()` and then evaluated with a `StandardEvaluationContext`, which permits type references, constructors, and method invocation, enabling arbitrary code execution.

## Source

HTTP request body: `RulePreviewRequest.expression()` (RulePreviewController line 16)

Data flows through:
1. RulePreviewController.preview() receives `@RequestBody RulePreviewRequest request` (line 16)
2. Passes `request.expression()` to `service.preview(request.expression(), ...)` (line 17)
3. RulePreviewService receives it as `expressionText` parameter (line 11)
4. Parsed as SpEL expression: `parser.parseExpression(expressionText)` (line 13)
5. Evaluated: `expression.getValue(context)` (line 14) — **sink**

## Fix

**Vulnerable code:**

```java
public Object preview(String expressionText, OrderContext order) {
    StandardEvaluationContext context = new StandardEvaluationContext(order);
    Expression expression = parser.parseExpression(expressionText);
    return expression.getValue(context);  // INJECTION SINK: evaluates user input as code
}
```

**Fixed code:**

```java
public Object preview(String expressionText, OrderContext order) {
    SimpleEvaluationContext context = SimpleEvaluationContext
        .forPropertyAccessors()
        .withRootObject(order)
        .build();
    Expression expression = parser.parseExpression(expressionText);
    return expression.getValue(context);
}
```

## Explanation

Replacing `StandardEvaluationContext` with `SimpleEvaluationContext` restricted to property access only eliminates access to type references, constructors, and method invocation. The attacker can no longer inject `T(java.lang.Runtime).getRuntime().exec(...)` or similar payload. `SimpleEvaluationContext.forPropertyAccessors()` restricts the context to read-only property access on the root object (the `OrderContext`), preventing execution of arbitrary code. The fix preserves the legitimate evaluation of property expressions like `total`, `tax`, or arithmetic comparisons on these properties while blocking code injection.

Note: Spring states that `SimpleEvaluationContext` restriction is "provided on a best-effort basis and does not guarantee that expression evaluation is safe." For maximum security, consider replacing dynamic expression evaluation entirely with a lookup table or strategy pattern mapping known-safe identifiers to predefined operations.

## Behaviour changes

**Import addition:** `SimpleEvaluationContext` must be imported from `org.springframework.expression.spel.support`. This is a new import required by the fix; Spring Framework dependencies already include it.

**Evaluation context type changed:** From `StandardEvaluationContext` to `SimpleEvaluationContext`, with construction via builder pattern. The evaluation behavior changes from allowing type references, method invocation, and constructor calls to read-only property access only. This is the intended security boundary and aligns with the guidance that SpEL against an untrusted source should be restricted to property access.

**API call chain changed:** Building the context now uses `SimpleEvaluationContext.forPropertyAccessors().withRootObject(order).build()` instead of direct constructor. This is required by the SimpleEvaluationContext API and does not alter the control flow beyond establishing a stricter evaluation context.

