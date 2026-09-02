using DynamicExpresso;

namespace Cases.CodeInjection;

public sealed class DiscountRuleEvaluator
{
    public object? Evaluate(string rule, decimal orderTotal)
    {
        var interpreter = new Interpreter();
        interpreter.SetVariable("orderTotal", orderTotal);
        interpreter.SetFunction("lookupRate", (System.Func<string, decimal>)LookupRate);

        // SAST FINDING: CWE-94 (Code Injection) reported here. Sink is the next statement.
        return interpreter.Eval(rule);
    }

    private static decimal LookupRate(string configKey)
    {
        return decimal.Parse(System.IO.File.ReadAllText(configKey));
    }
}
