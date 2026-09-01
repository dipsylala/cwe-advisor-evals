## Verdict
CONFIRMED. SpEL injection vulnerability at line 14: user-supplied expression text is parsed and evaluated without restriction, allowing arbitrary code execution through the `T()` operator and access to dangerous classes.

## Source
RulePreviewController receives `request.expression()` from untrusted HTTP input and passes it directly to RulePreviewService.preview(). The service parses and evaluates this expression with a StandardEvaluationContext that exposes the full SpEL evaluation context, including the `T()` operator for accessing arbitrary Java classes.

Attack vector: `T(java.lang.Runtime).getRuntime().exec("command")`

## Fix
Restrict the StandardEvaluationContext to prevent access to dangerous classes and methods:

```java
public Object preview(String expressionText, OrderContext order) {
    StandardEvaluationContext context = new StandardEvaluationContext(order);
    context.setMethodResolvers(Collections.emptyList());
    context.setConstructorResolvers(Collections.emptyList());
    context.setTypeLocator(new SimpleTypeLocator(Collections.emptySet()));
    Expression expression = parser.parseExpression(expressionText);
    return expression.getValue(context);
}
```

This prevents access to the `T()` operator (type access), constructor invocation, and arbitrary method resolution. The context is scoped to evaluate only properties and methods on the root `OrderContext` object.

## Explanation
CWE-94 occurs when user-supplied input is treated as executable code without validation. SpEL's `T()` operator is particularly dangerous as it allows direct access to any Java class on the classpath. By removing method resolvers, constructor resolvers, and restricting the type locator to an empty set, the expression can only access properties of the root object (OrderContext), preventing attackers from invoking arbitrary constructors or methods, including Runtime.exec().
