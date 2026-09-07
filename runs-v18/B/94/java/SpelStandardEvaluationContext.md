# CWE-94 Remediation Report: SpelStandardEvaluationContext

## Verdict

Exploitable. Untrusted user input from HTTP request is directly passed to Spring Expression Language parser and evaluated in a `StandardEvaluationContext`, which allows type references, constructor invocation, and method calls. An attacker can inject expressions like `T(java.lang.Runtime).getRuntime().exec("command")` to execute arbitrary code.

## Source

**Source**: `RulePreviewController.preview()` receives user-controlled `expression` field from HTTP `@RequestBody` request.

**Data Flow**:
1. `RulePreviewController.preview(@RequestBody RulePreviewRequest request)` receives untrusted input
2. Extracts `request.expression()` (untrusted string)
3. Passes to `RulePreviewService.preview(expressionText, order)` on line 17 of RulePreviewController
4. Line 13 of RulePreviewService: `parser.parseExpression(expressionText)` parses the untrusted expression
5. **Sink** - Line 14 of RulePreviewService: `expression.getValue(context)` evaluates the expression against `StandardEvaluationContext`, allowing type reference exploitation

**Attack Vector**: Expression like `T(java.lang.Runtime).getRuntime().exec("rm -rf /")` executes arbitrary OS commands with application privileges.

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
        SimpleEvaluationContext context = SimpleEvaluationContext
            .forReadOnlyDataBinding()
            .withRootObject(order)
            .build();
        Expression expression = parser.parseExpression(expressionText);
        return expression.getValue(context);
    }
}

record OrderContext(int total, int tax) {}
```

## Explanation

The fix replaces `StandardEvaluationContext` (which permits type references `T(...)`, constructor invocation, and method calls on any exposed object) with `SimpleEvaluationContext` configured for read-only data binding. `SimpleEvaluationContext` restricts evaluation to property access on the root object only, eliminating the ability to reference types, invoke constructors, or access dangerous methods like `Runtime.exec()`. The context is built using the builder pattern `SimpleEvaluationContext.forReadOnlyDataBinding().withRootObject(order).build()`, which binds the OrderContext data object as read-only properties accessible via expressions like `total` and `tax`, but prevents any type system access or constructor invocation.

## Behaviour changes

1. **Context Type Changed**: `StandardEvaluationContext` replaced with `SimpleEvaluationContext` - this is the primary security fix that eliminates type reference and method invocation capabilities.

2. **Constructor Pattern Changed**: Original used direct constructor `new StandardEvaluationContext(order)`. Fixed version uses builder pattern `SimpleEvaluationContext.forReadOnlyDataBinding().withRootObject(order).build()` to establish read-only binding.

3. **Import Changed**: Removed `org.springframework.expression.spel.support.StandardEvaluationContext`, added `org.springframework.expression.spel.support.SimpleEvaluationContext`.

4. **Expression Capability Restriction**: Expressions that previously could invoke type references or arbitrary methods now can only access root object properties. This is an intentional breaking change that restricts capability but maintains the legitimate use case (evaluating property-based expressions over OrderContext).

5. **No Return Value Changes**: `getValue(context)` still returns the evaluated expression result the same way; the method signature and return type are preserved.

6. **No Side Effects on OrderContext**: The OrderContext object is still accessible as the root object with properties `total` and `tax`, but only as read-only properties, not as constructor parameters or method targets.

**Reason**: All changes exist solely to eliminate type reference and method invocation vectors while preserving legitimate property access evaluation.

## Verification

**Compiler Check**: Syntax and import validation against Spring Framework 5.x+ API surface cannot be fully verified without Spring Framework jars in the classpath. However, the fix uses only documented public APIs from Spring Framework that have been stable since Spring 5.0: `SimpleEvaluationContext.forReadOnlyDataBinding()`, `.withRootObject()`, and `.build()` methods. These are standard Spring Expression Language APIs.

**Assumption**: The project already has Spring Framework dependencies available (as evidenced by existing imports of `org.springframework.expression.*` in the original code). The fix uses only standard Spring Expression Language APIs with no custom additions.

**Logic Verification**: The fix directly addresses the root cause identified in CWE-94 guidance: replacing unrestricted evaluation context (`StandardEvaluationContext`) with restricted context (`SimpleEvaluationContext`) that provides property-access-only semantics, preventing type reference and method invocation exploitation patterns.
