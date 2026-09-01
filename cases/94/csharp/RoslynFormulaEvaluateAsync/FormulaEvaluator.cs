using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;

namespace Cases.CodeInjection;

public sealed class FormulaEvaluator
{
    public System.Threading.Tasks.Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        var options = ScriptOptions.Default
            .WithImports("System", "System.IO")
            .WithReferences(typeof(InvoiceSample).Assembly);

        return CSharpScript.EvaluateAsync(expression, options, sample);
    }
}
