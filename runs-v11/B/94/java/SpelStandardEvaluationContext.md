## Verdict

**CONFIRMED**: CWE-94 code injection via Spring Expression Language (SpEL) using `StandardEvaluationContext`.

## Source

HTTP POST request body parameter `expression` in `RulePreviewController.preview()` passes untrusted user input directly to `RulePreviewService.preview(expressionText, ...)`.

## Fix

Replace `StandardEvaluationContext` with `SimpleEvaluationContext` to restrict expression evaluation to property access only, preventing type references, constructors, and method invocation.

**Original Code (lines 11-14):**
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
    SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
    context.setVariable("order", order);
    Expression expression = parser.parseExpression(expressionText);
    return expression.getValue(context, order);
}
```

Alternatively, if property access on the `order` object is required:
```java
public Object preview(String expressionText, OrderContext order) {
    SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
    Expression expression = parser.parseExpression(expressionText);
    return expression.getValue(context, order);
}
```

## Explanation

`StandardEvaluationContext` permits arbitrary type references via `T(java.lang.ClassName)`, method invocation, and constructor access, allowing attackers to inject expressions like `T(java.lang.Runtime).getRuntime().exec("command")` to achieve remote code execution.

`SimpleEvaluationContext` restricts evaluation to property access on the root object and variables, preventing type references and method invocation. This eliminates the code injection pathway while preserving legitimate property access on the `order` context object.

The fix requires importing `SimpleEvaluationContext` from `org.springframework.expression.spel.support`.

## Behaviour changes

- Property access on the `order` object remains functional (same as before)
- Type references via `T(...)` are now blocked and will throw an `EvaluationException`
- Method invocation is blocked and will throw an `EvaluationException`
- Constructor invocation is blocked and will throw an `EvaluationException`
- Bean references are blocked
- This tightens the security boundary while maintaining the intended functionality if only property access is required
