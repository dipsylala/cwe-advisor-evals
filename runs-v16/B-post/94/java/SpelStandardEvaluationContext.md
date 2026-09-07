## Verdict

Real, exploitable code injection vulnerability. Untrusted HTTP request input flows directly into `SpelExpressionParser.parseExpression()` and is evaluated against a `StandardEvaluationContext`, which permits type references and method invocation. An attacker can inject expressions like `T(java.lang.Runtime).getRuntime().exec("malicious command")` to execute arbitrary code.

## Source

`RulePreviewController.java`, line 17: The `@RequestBody` annotation receives untrusted user input as a JSON string `request.expression()` passed to `RulePreviewService.preview()`.

## Fix

Replace `StandardEvaluationContext` with `SimpleEvaluationContext` to restrict expression evaluation to property access only, preventing type references and method invocation:

**Vulnerable code** (line 12-14 in RulePreviewService.java):
```java
StandardEvaluationContext context = new StandardEvaluationContext(order);
Expression expression = parser.parseExpression(expressionText);
return expression.getValue(context);
```

**Fixed code**:
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

**Changes required**:
1. Replace import: `StandardEvaluationContext` → `SimpleEvaluationContext`
2. Replace context creation: Use `SimpleEvaluationContext.forReadOnlyDataBinding()` with `.withRootObject(order).build()`

## Explanation

`StandardEvaluationContext` permits dangerous capabilities: type references (e.g. `T(java.lang.Runtime)`), constructor invocation, and bean method calls. `SimpleEvaluationContext` with `forReadOnlyDataBinding()` restricts evaluation to read-only property access on the root object, eliminating the attack surface. The attacker can no longer inject type references or invoke arbitrary methods. Property access to `order.total` and `order.tax` remains available for legitimate expressions.

## Behaviour changes

The API contract changes minimally: `SimpleEvaluationContext` returns expressions evaluated as property access only. Legitimate expressions that read properties (`order.total`, `order.tax`) continue to work. Expressions that attempted type references, constructors, or method invocation (whether intentional or injected) now evaluate to `null` rather than executing code. This is the intended defense. No return type or exception contract changes occur; the return type remains `Object`.
