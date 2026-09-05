## Verdict
The vulnerability is confirmed. Line 43 passes database-loaded code directly to `GroovyShell.evaluate()`, which compiles and executes arbitrary Groovy code without restriction. Even though the formula is "admin-configured," a compromised database or malicious admin can inject arbitrary code that accesses the filesystem, environment variables, or executes system commands.

## Source
Line 43: `Object result = shell.evaluate(customFormula);`

The `customFormula` string is loaded from `PricingRuleRepository.findFormulaByProductId()` and passed directly to `shell.evaluate()`. The GroovyShell is created with a Binding containing only `basePrice` and `quantity`, but GroovyShell has no runtime restrictions on what code can be compiled and executed. Groovy's ClassLoader and MOP allow access to arbitrary Java APIs.

## Fix
Replace Groovy's full code evaluation with a dedicated expression language library that safely evaluates mathematical expressions only. Use Apache Commons JEXL with a restricted set of functions:

```java
import org.apache.commons.jexl3.*;

public BigDecimal computePrice(String productId, BigDecimal basePrice, int quantity) {
    String customFormula = pricingRuleRepository.findFormulaByProductId(productId);
    if (customFormula == null || customFormula.isBlank()) {
        return basePrice;
    }

    try {
        JexlEngine jexl = new JexlBuilder().create();
        
        // Create a context with only safe variables
        JexlContext context = new MapContext();
        context.set("basePrice", basePrice);
        context.set("quantity", quantity);
        
        // Parse and evaluate the expression (no Java method calls allowed)
        JexlExpression expr = jexl.createExpression(customFormula);
        Object result = expr.evaluate(context);

        if (result instanceof BigDecimal) {
            return (BigDecimal) result;
        }
        if (result instanceof Number) {
            return BigDecimal.valueOf(((Number) result).doubleValue());
        }
        return basePrice;
    } catch (JexlException e) {
        // Formula parsing/evaluation failed; return base price
        return basePrice;
    }
}
```

Add dependency: `org.apache.commons:commons-jexl3:3.3.1` (or later).

Alternative: Replace Groovy entirely with a math-only parser like `EvalEx` if JEXL's expression syntax does not match your admin interface.

## Explanation
Groovy's `GroovyShell.evaluate()` compiles user-provided strings into executable bytecode with full JVM access. There is no runtime sandbox; GroovyShell respects Java's access modifiers but does not prevent reflection, ClassLoader manipulation, or system API calls. A formula like `"java.lang.Runtime.getRuntime().exec('cmd')"` executes successfully.

Apache Commons JEXL is designed specifically for safe expression evaluation. It restricts execution to operator evaluation and function calls on objects passed in the context (`basePrice`, `quantity`). It does not allow method invocation on arbitrary classes, static imports, or Java reflection. The admin formula `"basePrice * (quantity > 10 ? 0.9 : 1.0)"` evaluates correctly in JEXL; injection attempts like `"Runtime.getRuntime().exec('...')"` fail at parse time because `Runtime` is not in the context.

Use error handling to gracefully degrade to base price if a malformed or hostile formula is encountered, rather than crashing or leaking stack traces.
