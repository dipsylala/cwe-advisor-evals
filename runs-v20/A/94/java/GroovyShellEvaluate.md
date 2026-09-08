## Verdict

Confirmed. `computePrice()` passes `customFormula` - a string loaded verbatim from the `pricing_rules` table - directly into `new GroovyShell(binding).evaluate(customFormula)`. `GroovyShell.evaluate()` compiles and runs its argument as a full Groovy script with the permissions of the host JVM. Anything that can influence the stored formula text (a compromised admin session, a CSRF against the pricing-config screen, a SQL injection or migration bug that lets an attacker write to `pricing_rules`, or simply an over-broad "admin" role) gets arbitrary code execution, not just a pricing tweak - e.g. a formula value of `"basePrice * 1; Runtime.getRuntime().exec('...')"` or `"new File('/etc/passwd').text; basePrice"` runs with no sandbox at all.

## Source

`String customFormula = pricingRuleRepository.findFormulaByProductId(productId);` (`PricingFormulaEvaluator.java:32`), flowing unmodified into the sink at `PricingFormulaEvaluator.java:43`, `shell.evaluate(customFormula)`.

## Fix

### File: PricingFormulaEvaluator.java
```java
package com.example.pricing;

import java.math.BigDecimal;

/**
 * Evaluates the admin-configured "custom pricing formula" against a specific
 * order's base price and quantity. Admins manage the formula text through
 * the pricing configuration screen; it is stored verbatim in the
 * pricing_rules table and loaded back in here at quote time.
 */
public class PricingFormulaEvaluator {

    private final PricingRuleRepository pricingRuleRepository;

    public PricingFormulaEvaluator(PricingRuleRepository pricingRuleRepository) {
        this.pricingRuleRepository = pricingRuleRepository;
    }

    /**
     * Computes the final unit price for a product by running the merchant's
     * custom pricing formula, e.g. "basePrice * (quantity > 10 ? 0.9 : 1.0)".
     *
     * @param productId the product whose custom formula should be applied
     * @param basePrice the catalog base price for the product
     * @param quantity  the quantity being quoted
     * @return the computed price, or basePrice if no custom formula is configured
     */
    public BigDecimal computePrice(String productId, BigDecimal basePrice, int quantity) {
        String customFormula = pricingRuleRepository.findFormulaByProductId(productId);
        if (customFormula == null || customFormula.isBlank()) {
            return basePrice;
        }

        return SafeFormulaExpressionEvaluator.evaluate(customFormula, basePrice, quantity);
    }
}
```

### File: SafeFormulaExpressionEvaluator.java
```java
package com.example.pricing;

import java.math.BigDecimal;
import java.math.MathContext;
import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates a small, fixed arithmetic-formula grammar - numeric literals,
 * the two known variables {@code basePrice} and {@code quantity}, the
 * operators {@code + - * /}, comparisons, parentheses, and the ternary
 * {@code condition ? a : b} operator - without invoking any general-purpose
 * script or expression engine.
 *
 * The grammar below has no way to name a class, call a method, read a file,
 * or perform any I/O: every production either consumes a literal/variable or
 * combines two already-evaluated numbers with a fixed arithmetic operator.
 * A formula string can therefore never do more than compute a number from
 * basePrice and quantity, so unlike a Groovy/JavaScript/JEXL evaluator there
 * is no code-execution surface to sandbox in the first place.
 */
final class SafeFormulaExpressionEvaluator {

    private final String source;
    private final BigDecimal basePrice;
    private final BigDecimal quantity;
    private final List<Token> tokens;
    private int position;

    private SafeFormulaExpressionEvaluator(String source, BigDecimal basePrice, int quantity) {
        this.source = source;
        this.basePrice = basePrice;
        this.quantity = BigDecimal.valueOf(quantity);
        this.tokens = tokenize(source);
        this.position = 0;
    }

    /**
     * Parses and evaluates {@code formula} against the given variables.
     *
     * @throws IllegalArgumentException if the formula is not a well-formed
     *                                   expression in the supported grammar
     */
    static BigDecimal evaluate(String formula, BigDecimal basePrice, int quantity) {
        SafeFormulaExpressionEvaluator evaluator = new SafeFormulaExpressionEvaluator(formula, basePrice, quantity);
        Object result = evaluator.parseExpression();
        evaluator.expectEnd();
        if (!(result instanceof BigDecimal)) {
            throw new IllegalArgumentException("Formula must evaluate to a number: " + formula);
        }
        return (BigDecimal) result;
    }

    // expression := comparison ( '?' expression ':' expression )?
    private Object parseExpression() {
        Object condition = parseComparison();
        if (peekType() == TokenType.QUESTION) {
            advance();
            Object whenTrue = parseExpression();
            expect(TokenType.COLON);
            Object whenFalse = parseExpression();
            if (!(condition instanceof Boolean)) {
                throw new IllegalArgumentException("Ternary condition must be a comparison: " + source);
            }
            return ((Boolean) condition) ? whenTrue : whenFalse;
        }
        return condition;
    }

    // comparison := additive ( ('<' | '<=' | '>' | '>=' | '==' | '!=') additive )?
    private Object parseComparison() {
        BigDecimal left = parseAdditive();
        TokenType type = peekType();
        if (isComparisonOperator(type)) {
            advance();
            BigDecimal right = parseAdditive();
            return applyComparison(type, left, right);
        }
        return left;
    }

    // additive := term ( ('+' | '-') term )*
    private BigDecimal parseAdditive() {
        BigDecimal value = parseTerm();
        while (peekType() == TokenType.PLUS || peekType() == TokenType.MINUS) {
            TokenType op = advance().type;
            BigDecimal right = parseTerm();
            value = (op == TokenType.PLUS) ? value.add(right) : value.subtract(right);
        }
        return value;
    }

    // term := unary ( ('*' | '/') unary )*
    private BigDecimal parseTerm() {
        BigDecimal value = parseUnary();
        while (peekType() == TokenType.STAR || peekType() == TokenType.SLASH) {
            TokenType op = advance().type;
            BigDecimal right = parseUnary();
            value = (op == TokenType.STAR) ? value.multiply(right) : value.divide(right, MathContext.DECIMAL64);
        }
        return value;
    }

    // unary := '-' unary | primary
    private BigDecimal parseUnary() {
        if (peekType() == TokenType.MINUS) {
            advance();
            return parseUnary().negate();
        }
        return parsePrimary();
    }

    // primary := NUMBER | 'basePrice' | 'quantity' | '(' expression ')'
    private BigDecimal parsePrimary() {
        Token token = advance();
        switch (token.type) {
            case NUMBER:
                return new BigDecimal(token.text);
            case IDENT:
                if ("basePrice".equals(token.text)) {
                    return basePrice;
                }
                if ("quantity".equals(token.text)) {
                    return quantity;
                }
                throw new IllegalArgumentException("Unknown variable '" + token.text + "' in formula: " + source);
            case LPAREN:
                Object inner = parseExpression();
                expect(TokenType.RPAREN);
                if (!(inner instanceof BigDecimal)) {
                    throw new IllegalArgumentException("Expected a numeric expression in formula: " + source);
                }
                return (BigDecimal) inner;
            default:
                throw new IllegalArgumentException("Unexpected token '" + token.text + "' in formula: " + source);
        }
    }

    private boolean applyComparison(TokenType type, BigDecimal left, BigDecimal right) {
        int cmp = left.compareTo(right);
        switch (type) {
            case LT: return cmp < 0;
            case LE: return cmp <= 0;
            case GT: return cmp > 0;
            case GE: return cmp >= 0;
            case EQ: return cmp == 0;
            case NE: return cmp != 0;
            default: throw new IllegalStateException("Not a comparison operator: " + type);
        }
    }

    private boolean isComparisonOperator(TokenType type) {
        return type == TokenType.LT || type == TokenType.LE || type == TokenType.GT
                || type == TokenType.GE || type == TokenType.EQ || type == TokenType.NE;
    }

    private TokenType peekType() {
        return position < tokens.size() ? tokens.get(position).type : TokenType.END;
    }

    private Token advance() {
        if (position >= tokens.size()) {
            throw new IllegalArgumentException("Unexpected end of formula: " + source);
        }
        return tokens.get(position++);
    }

    private void expect(TokenType type) {
        Token token = advance();
        if (token.type != type) {
            throw new IllegalArgumentException("Expected '" + type + "' in formula: " + source);
        }
    }

    private void expectEnd() {
        if (peekType() != TokenType.END) {
            throw new IllegalArgumentException("Unexpected trailing content in formula: " + source);
        }
    }

    private enum TokenType {
        NUMBER, IDENT, PLUS, MINUS, STAR, SLASH, LPAREN, RPAREN,
        QUESTION, COLON, LT, LE, GT, GE, EQ, NE, END
    }

    private static final class Token {
        final TokenType type;
        final String text;

        Token(TokenType type, String text) {
            this.type = type;
            this.text = text;
        }
    }

    private static List<Token> tokenize(String source) {
        List<Token> result = new ArrayList<>();
        int i = 0;
        int length = source.length();
        while (i < length) {
            char c = source.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
            } else if (Character.isDigit(c) || c == '.') {
                int start = i;
                while (i < length && (Character.isDigit(source.charAt(i)) || source.charAt(i) == '.')) {
                    i++;
                }
                result.add(new Token(TokenType.NUMBER, source.substring(start, i)));
            } else if (Character.isLetter(c)) {
                int start = i;
                while (i < length && Character.isLetterOrDigit(source.charAt(i))) {
                    i++;
                }
                result.add(new Token(TokenType.IDENT, source.substring(start, i)));
            } else {
                switch (c) {
                    case '+': result.add(new Token(TokenType.PLUS, "+")); i++; break;
                    case '-': result.add(new Token(TokenType.MINUS, "-")); i++; break;
                    case '*': result.add(new Token(TokenType.STAR, "*")); i++; break;
                    case '/': result.add(new Token(TokenType.SLASH, "/")); i++; break;
                    case '(': result.add(new Token(TokenType.LPAREN, "(")); i++; break;
                    case ')': result.add(new Token(TokenType.RPAREN, ")")); i++; break;
                    case '?': result.add(new Token(TokenType.QUESTION, "?")); i++; break;
                    case ':': result.add(new Token(TokenType.COLON, ":")); i++; break;
                    case '<':
                        if (i + 1 < length && source.charAt(i + 1) == '=') {
                            result.add(new Token(TokenType.LE, "<=")); i += 2;
                        } else {
                            result.add(new Token(TokenType.LT, "<")); i++;
                        }
                        break;
                    case '>':
                        if (i + 1 < length && source.charAt(i + 1) == '=') {
                            result.add(new Token(TokenType.GE, ">=")); i += 2;
                        } else {
                            result.add(new Token(TokenType.GT, ">")); i++;
                        }
                        break;
                    case '=':
                        if (i + 1 < length && source.charAt(i + 1) == '=') {
                            result.add(new Token(TokenType.EQ, "==")); i += 2;
                        } else {
                            throw new IllegalArgumentException("Unsupported operator '=' at position " + i + " in formula: " + source);
                        }
                        break;
                    case '!':
                        if (i + 1 < length && source.charAt(i + 1) == '=') {
                            result.add(new Token(TokenType.NE, "!=")); i += 2;
                        } else {
                            throw new IllegalArgumentException("Unsupported operator '!' at position " + i + " in formula: " + source);
                        }
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported character '" + c + "' in formula: " + source);
                }
            }
        }
        return result;
    }
}
```

## Explanation

The original code handed a stored string straight to `GroovyShell.evaluate()`, which compiles and runs it as a full Groovy script - able to reference any class on the classpath (`java.lang.Runtime`, `java.io.File`, reflection, etc.) with no restriction. Trying to keep Groovy and lock it down with a `SecureASTCustomizer`/`CompilerConfiguration` sandbox was rejected: that mechanism is an AST-level denylist that has a history of bypasses (metaprogramming, `invokeMethod`, category classes), so it narrows the attack surface without closing it, and it would still require justifying a new sandbox configuration on every future edit to the formula language.

The fix instead removes the scripting engine entirely. `SafeFormulaExpressionEvaluator` is a small hand-written recursive-descent parser whose grammar is closed by construction: a `primary` can only be a numeric literal, the identifier `basePrice`, the identifier `quantity`, or a parenthesized sub-expression, and every operator (`+ - * /`, the six comparisons, and `?:`) combines two already-evaluated `BigDecimal`/`boolean` values - there is no production that can name a class, invoke a method, or perform I/O. This preserves the documented formula language (`"basePrice * (quantity > 10 ? 0.9 : 1.0)"` still evaluates exactly as before, arithmetic and ternaries included) while making arbitrary code execution structurally impossible rather than merely filtered. An unrecognized identifier, unsupported character, or malformed expression raises `IllegalArgumentException` instead of silently falling back, so a bad admin-entered formula fails loudly at quote time rather than masking a business-logic mistake as a plain `basePrice` return.

Verified by tracing evaluation of the documented example formula through the grammar by hand: `parseExpression` reads the `additive` `basePrice`, sees `*`, reads `parsePrimary` for the parenthesized group, which recurses into `parseExpression` -> `parseComparison` (`quantity > 10`, a `Boolean`) -> sees `?`, evaluates the ternary to `0.9` or `1.0` depending on `quantity`, and the outer `parseTerm` multiplies that `BigDecimal` result by `basePrice`, matching the original Groovy result for the same inputs.
