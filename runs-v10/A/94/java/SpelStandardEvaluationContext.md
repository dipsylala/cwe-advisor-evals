## Verdict

**Confirmed CWE-94:** The `RulePreviewService.preview()` method accepts untrusted user-supplied expression text from the HTTP request and evaluates it directly as Spring Expression Language (SpEL) without validation or sandboxing. This allows arbitrary code execution.

The vulnerable call chain:
1. `RulePreviewController.preview()` receives `@RequestBody` with user-controlled `expression` string
2. Passes it unsanitized to `RulePreviewService.preview(expressionText, order)`
3. `RulePreviewService` parses and evaluates the expression on line 14 with full method access available

An attacker can inject SpEL expressions such as `T(java.lang.Runtime).getRuntime().exec('...')` to achieve remote code execution.

## Source

**File:** `RulePreviewService.java`, line 14  
**Vulnerable code:**
```
Expression expression = parser.parseExpression(expressionText);
return expression.getValue(context);
```

The parameter `expressionText` flows directly from user input without validation. The `StandardEvaluationContext` is created with default settings that permit method invocation and type access.

## Fix

Replace the `preview()` method to restrict SpEL evaluation capabilities. Use `SimpleEvaluationContext` instead of `StandardEvaluationContext`, which disables method invocations and constructor calls by default:

```java
import org.springframework.expression.spel.support.SimpleEvaluationContext;

public Object preview(String expressionText, OrderContext order) {
    SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding()
        .withRootObject(order)
        .build();
    Expression expression = parser.parseExpression(expressionText);
    return expression.getValue(context);
}
```

The `SimpleEvaluationContext.forReadOnlyDataBinding()` configuration:
- Allows property access and method invocation only on the root object (order)
- Disables access to type references via `T()`
- Disables constructor calls
- Blocks reflection-based method execution

This confines expression evaluation to safe, intentional property reads on the `OrderContext` object (such as `total` and `tax`), preventing injection of arbitrary Java method calls or runtime code execution.

## Explanation

SpEL is designed for configuration and template scenarios, not for evaluating untrusted user input. The standard `StandardEvaluationContext` exposes the full Java type system to expressions, allowing attackers to instantiate arbitrary classes and invoke arbitrary methods.

`SimpleEvaluationContext` was introduced precisely for this use case—when you need to evaluate expressions over application data without trusting the expression source. By restricting the context to read-only property access on a specific root object, the remediation eliminates the code generation attack surface while preserving the ability to safely evaluate expressions that reference object properties.

If dynamic expression evaluation is not needed at all, the strongest fix would be to replace SpEL with property path templates or a whitelist of predefined expressions—but if SpEL must be used with user input, `SimpleEvaluationContext` with appropriate restrictions is the recommended mitigation.
