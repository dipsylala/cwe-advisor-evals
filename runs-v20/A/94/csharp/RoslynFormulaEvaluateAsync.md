## Verdict
Confirmed. `FormulaEvaluator.EvaluateAsync` compiles and runs the caller-supplied `expression` string as live C# script code via `CSharpScript.EvaluateAsync`, with `System` and `System.IO` imported and a reference to the sample's assembly. Any client of the `/api/formulas/preview` endpoint can submit arbitrary C# (file access, process launch, reflection, etc.) as the "formula" and have the server execute it - full remote code execution, not just formula evaluation.

## Source
`FormulaPreviewController.Preview` takes `request.Expression` straight from the deserialized JSON request body (`FormulaPreviewRequest.Expression`, entirely attacker-controlled) and passes it unmodified to `_evaluator.EvaluateAsync(request.Expression, ...)`, which forwards it to `CSharpScript.EvaluateAsync(expression, options, sample)`. There is no parsing, allowlist, or sandboxing between the HTTP input and the Roslyn script compiler/executor - the sink is the dynamic compilation and execution of that string as code.

## Fix

### File: FormulaEvaluator.cs
```csharp
using System;
using System.Globalization;
using System.Threading.Tasks;

namespace Cases.CodeInjection;

public sealed class FormulaEvaluator
{
    public Task<object?> EvaluateAsync(string expression, InvoiceSample sample)
    {
        var parser = new SafeFormulaParser(expression, sample);
        var result = parser.ParseAndEvaluate();
        return Task.FromResult<object?>(result);
    }

    // Recursive-descent evaluator for a restricted arithmetic grammar:
    //   expression := term (('+' | '-') term)*
    //   term       := factor (('*' | '/') factor)*
    //   factor     := number | identifier | '(' expression ')' | ('+' | '-') factor
    //   identifier := "Total" | "Tax"
    // No code is compiled or executed - only numeric literals, the two known
    // invoice fields, and the four arithmetic operators are recognized.
    private sealed class SafeFormulaParser
    {
        private readonly string _text;
        private readonly InvoiceSample _sample;
        private int _pos;

        public SafeFormulaParser(string text, InvoiceSample sample)
        {
            _text = text ?? throw new ArgumentNullException(nameof(text));
            _sample = sample;
            _pos = 0;
        }

        public decimal ParseAndEvaluate()
        {
            var value = ParseExpression();
            SkipWhitespace();
            if (_pos != _text.Length)
            {
                throw new FormatException($"Unexpected character at position {_pos} in formula.");
            }

            return value;
        }

        private decimal ParseExpression()
        {
            var value = ParseTerm();
            while (true)
            {
                SkipWhitespace();
                var c = Peek();
                if (c == '+')
                {
                    _pos++;
                    value += ParseTerm();
                }
                else if (c == '-')
                {
                    _pos++;
                    value -= ParseTerm();
                }
                else
                {
                    break;
                }
            }

            return value;
        }

        private decimal ParseTerm()
        {
            var value = ParseFactor();
            while (true)
            {
                SkipWhitespace();
                var c = Peek();
                if (c == '*')
                {
                    _pos++;
                    value *= ParseFactor();
                }
                else if (c == '/')
                {
                    _pos++;
                    var divisor = ParseFactor();
                    if (divisor == 0)
                    {
                        throw new DivideByZeroException("Formula divides by zero.");
                    }

                    value /= divisor;
                }
                else
                {
                    break;
                }
            }

            return value;
        }

        private decimal ParseFactor()
        {
            SkipWhitespace();
            var c = Peek();

            if (c == '-')
            {
                _pos++;
                return -ParseFactor();
            }

            if (c == '+')
            {
                _pos++;
                return ParseFactor();
            }

            if (c == '(')
            {
                _pos++;
                var value = ParseExpression();
                SkipWhitespace();
                if (Peek() != ')')
                {
                    throw new FormatException("Expected ')' in formula.");
                }

                _pos++;
                return value;
            }

            if (char.IsDigit(c) || c == '.')
            {
                return ParseNumber();
            }

            if (char.IsLetter(c))
            {
                return ParseIdentifier();
            }

            throw new FormatException($"Unexpected character '{c}' in formula.");
        }

        private decimal ParseNumber()
        {
            var start = _pos;
            while (_pos < _text.Length && (char.IsDigit(_text[_pos]) || _text[_pos] == '.'))
            {
                _pos++;
            }

            var slice = _text.Substring(start, _pos - start);
            if (!decimal.TryParse(slice, NumberStyles.Number, CultureInfo.InvariantCulture, out var value))
            {
                throw new FormatException($"Invalid number '{slice}' in formula.");
            }

            return value;
        }

        private decimal ParseIdentifier()
        {
            var start = _pos;
            while (_pos < _text.Length && char.IsLetterOrDigit(_text[_pos]))
            {
                _pos++;
            }

            var name = _text.Substring(start, _pos - start);
            return name switch
            {
                "Total" => _sample.Total,
                "Tax" => _sample.Tax,
                _ => throw new FormatException($"Unknown identifier '{name}' in formula. Allowed identifiers: Total, Tax."),
            };
        }

        private char Peek() => _pos < _text.Length ? _text[_pos] : '\0';

        private void SkipWhitespace()
        {
            while (_pos < _text.Length && char.IsWhiteSpace(_text[_pos]))
            {
                _pos++;
            }
        }
    }
}
```

## Explanation
The vulnerable design compiled and ran the client's string as C# through the Roslyn scripting API (`CSharpScript.EvaluateAsync`), which is general-purpose code execution - there is no way to "sanitize" a string and still safely hand it to a script compiler, because any restriction that still permits real arithmetic expressions (variables, parentheses, operators) also permits arbitrary method calls, field/property access, and namespace-qualified type references reachable through the imported `System`/`System.IO` namespaces and the referenced assembly. The only sound fix is to stop treating the input as code at all.

The replacement keeps the same public signature (`EvaluateAsync(string expression, InvoiceSample sample)` returning `Task<object?>`) so `FormulaPreviewController` needs no change, but internally it no longer calls into Roslyn or any other dynamic-compilation/eval mechanism. Instead it parses the string with a small hand-written recursive-descent parser limited to a fixed grammar: decimal literals, `+ - * /`, parentheses, and exactly two identifiers, `Total` and `Tax`, which are resolved directly against the `InvoiceSample` passed in rather than through reflection or dynamic member lookup. This is not a security-only allowlist bolted onto an otherwise-unsafe path; it is the complete grammar the "formula" domain is defined over, so no legitimate formula input is rejected while every non-arithmetic construct (identifiers other than the two known fields, method calls, string literals, statements, etc.) fails to parse and raises `FormatException` rather than being executed. Division by zero is rejected explicitly instead of surfacing a runtime exception from arbitrary code. Because no assembly is compiled and no script host executes attacker text, the code-injection sink is eliminated rather than filtered.
