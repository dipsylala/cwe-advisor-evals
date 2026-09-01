package cases.codeinjection;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

public class RulePreviewService {
    private final ExpressionParser parser = new SpelExpressionParser();

    public Object preview(String expressionText, OrderContext order) {
        StandardEvaluationContext context = new StandardEvaluationContext(order);
        Expression expression = parser.parseExpression(expressionText);
        return expression.getValue(context);
    }
}
