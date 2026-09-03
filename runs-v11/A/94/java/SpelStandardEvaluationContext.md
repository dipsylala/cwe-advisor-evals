## Verdict

CONFIRMED

## Source

Line 14 in `RulePreviewService.java` evaluates user-supplied SpEL expressions with full evaluation context capabilities:

```java
return expression.getValue(context);
```

The `expressionText` parameter originates from untrusted HTTP input (the request body at `RulePreviewController.java` line 17), flows directly to `parser.parseExpression(expressionText)` at line 13, and is then evaluated against a `StandardEvaluationContext` at line 14. `StandardEvaluationContext` permits access to arbitrary object methods, properties, and system operations, making it a direct code-execution sink.

## Fix

Replace `StandardEvaluationContext` with `SimpleEvaluationContext`, which restricts evaluation to property access and method invocation on only the explicitly registered objects, and disable method invocation entirely:

```java
public Object preview(String expressionText, OrderContext order) {
    SimpleEvaluationContext context = SimpleEvaluationContext
        .forReadOnlyDataBinding()
        .withRootObject(order)
        .build();
    Expression expression = parser.parseExpression(expressionText);
    return expression.getValue(context);
}
```

Alternatively, if method calls on `order` are required, use `SimpleEvaluationContext.forReadWriteDataBinding()`, but disable static method invocation by not registering any `MethodResolver` that permits it. For cases requiring full SpEL, implement an allowlist parser that rejects expressions containing method calls, field access, or type references before parsing.

## Explanation

`StandardEvaluationContext` grants unrestricted access to bean properties, static methods, type constructors, and system operations. An attacker supplying `T(java.lang.Runtime).getRuntime().exec('...')` or similar payloads can achieve arbitrary code execution. `SimpleEvaluationContext.forReadOnlyDataBinding()` restricts evaluation to reading properties of the registered root object (`order`), preventing method invocation, constructor calls, and access to system classes. If the application genuinely needs method calls or write access, this fix should be paired with an upstream input validation layer that constrains the expression grammar to a safe subset (e.g., property access only, no operators, no string literals), enforced before parsing.
