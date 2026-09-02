def evaluate_formula(expression, variables):
    context = dict(variables)
    # SAST FINDING: CWE-94 (Code Injection) reported here. Sink is the next statement.
    return eval(expression, {"__builtins__": {}}, context)
