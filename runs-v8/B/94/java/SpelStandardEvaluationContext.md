## Verdict

Exploitable

## Source

User-supplied expression string from HTTP request body (`RulePreviewRequest.expression()`), received in `RulePreviewController.preview()` and passed to `RulePreviewService.preview(expressionText, order)`.

## Fix

**Vulnerable Code (Line 11–14):**
```java
public Object preview(String expressionText, OrderContext order) {
    StandardEvaluationContext context = new StandardEvaluationContext(order);
    Expression expression = parser.parseExpression(expressionText);
    return expression.getValue(context);
}
```

**Fixed Code:**
```java
public Object preview(String expressionText, OrderContext order) {
    // Validate expression against allowlist
    if (!isAllowedExpression(expressionText)) {
        throw new IllegalArgumentException("Expression not permitted");
    }
    
    SimpleEvaluationContext context = SimpleEvaluationContext
        .forReadOnlyDataBinding()
        .build();
    Expression expression = parser.parseExpression(expressionText);
    return expression.getValue(context, order);
}

private boolean isAllowedExpression(String expression) {
    // Allowlist: only property access (dotted names, no method calls or type references)
    return expression.matches("^[a-zA-Z_][a-zA-Z0-9_.]*$");
}
```

## Explanation

`StandardEvaluationContext` permits type references and method invocation, allowing expressions like `T(java.lang.Runtime).getRuntime().exec(...)` to execute arbitrary code. The fix replaces it with `SimpleEvaluationContext` configured with `forReadOnlyDataBinding()`, which restricts evaluation to read-only property access on the supplied object only, eliminating access to type references, constructors, and method calls. An allowlist validation layer checks that the expression matches a simple property-access pattern before parsing, providing defence-in-depth against bypass attempts. The context is now passed to `getValue(context, order)` to supply the root object for property binding.

## Behaviour changes

1. **Expression scope restricted**: `StandardEvaluationContext` allowed arbitrary type references and method calls; `SimpleEvaluationContext` restricts to property access on the supplied `order` object only. Expressions attempting type references, constructors, or method invocation now fail.
2. **Allowlist validation added**: The new `isAllowedExpression()` check rejects expressions containing characters outside `[a-zA-Z0-9_.]`, blocking injection attempts. This is a new validation gate with no predecessor in the original code.
3. **Read-only evaluation**: Expressions are evaluated in read-only mode; property writes are not permitted.
4. **Root object binding**: The `order` parameter is now explicitly bound as the root object in `getValue(context, order)`, where the original `StandardEvaluationContext(order)` constructor implicitly set it as the root. Semantically equivalent; the expression now reads properties from `order` through the restricted context.
