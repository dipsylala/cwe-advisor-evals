## Verdict

Confirmed. `RulePreviewService.preview()` parses a fully attacker-controlled string (`RulePreviewRequest.expression()`, taken directly from the JSON request body with no validation) as a Spring Expression Language (SpEL) expression and evaluates it against a `StandardEvaluationContext`. `StandardEvaluationContext` permits arbitrary method invocation, constructor calls, static/type references (`T(...)`), and bean references during evaluation, so a request such as `{"expression": "T(java.lang.Runtime).getRuntime().exec('...')"}` results in arbitrary code execution on the server. This is CWE-94, Improper Control of Generation of Code (SpEL injection).

## Source

`request.expression()` in `RulePreviewController.preview()` — the `expression` field of the `@RequestBody RulePreviewRequest`, i.e. attacker-controlled input from the HTTP request body — flows unmodified into `RulePreviewService.preview(String expressionText, OrderContext order)`, where it is parsed by `SpelExpressionParser.parseExpression()` and evaluated via `Expression.getValue(context)` against a `StandardEvaluationContext` (line 14 in `RulePreviewService.java`).

## Fix

### File: RulePreviewService.java
```java
package cases.codeinjection;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

public class RulePreviewService {
    private final ExpressionParser parser = new SpelExpressionParser();

    public Object preview(String expressionText, OrderContext order) {
        SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        context.setRootObject(order);
        Expression expression = parser.parseExpression(expressionText);
        return expression.getValue(context);
    }
}
```

## Explanation

The root cause is not the parsing of untrusted text as SpEL (that is unavoidable for a "rule preview" feature) but the evaluation context: `StandardEvaluationContext` is the full-power context Spring itself documents as unsafe for untrusted input, because it resolves arbitrary reflective methods, constructors, static members via `T(...)`, and registered beans, giving an evaluated expression the same capabilities as arbitrary Java code.

`SimpleEvaluationContext` is the context Spring's own documentation recommends specifically for evaluating expressions from external, untrusted sources. Built with `forReadOnlyDataBinding()`, it configures only a read-only `DataBindingPropertyAccessor` and no method resolvers, no constructor resolver, and no type locator — so reflective method invocation, `new X(...)`, `T(java.lang.Runtime)`-style type references, and `@beanName` bean references are all structurally unresolvable, regardless of what string is supplied. Core SpEL language features unrelated to reflection — property/field access via getters (`total`, `tax`), arithmetic, and relational/logical operators — continue to work, so legitimate rule expressions such as `total > 100` still evaluate correctly against the `OrderContext` root object.

The root object is supplied via `context.setRootObject(order)` rather than the `StandardEvaluationContext(Object)` constructor, since `SimpleEvaluationContext` does not offer that convenience constructor; `setRootObject` is inherited from the same base evaluation-context implementation and has identical effect.

No allowlist or regex filtering of the expression string was added: a syntactic filter over SpEL text is trivially bypassable and would still leave the same reflective evaluation context intact for whatever it fails to catch. Restricting the context itself removes the dangerous capabilities at the evaluation layer, which is the primary defense here, not a supplementary one.
