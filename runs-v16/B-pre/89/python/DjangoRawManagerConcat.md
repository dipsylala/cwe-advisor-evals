## Verdict

Exploitable.

## Source

`request.GET.get("email")` at line 12 provides untrusted user input from an HTTP GET parameter.

## Fix

**Vulnerable code** (line 16-18):
```python
sql = f"SELECT id, placed_at, total_cents, status FROM shop_order WHERE customer_email = '{email}'"
# SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
orders = Order.objects.raw(sql)
```

**Fixed code**:
```python
sql = "SELECT id, placed_at, total_cents, status FROM shop_order WHERE customer_email = %s"
orders = Order.objects.raw(sql, [email])
```

## Explanation

The fix replaces f-string interpolation with Django's parameterized query interface. The `%s` placeholder instructs the database driver to treat the value as data, never as executable SQL structure. By passing `email` as a separate argument in the parameter list, the driver insulates the untrusted input from SQL parsing, preventing an attacker from injecting operators, keywords, or clauses through the email field. An attacker attempting `' OR '1'='1` will now be treated as a literal email value and safely matched or not matched against the database.

## Behaviour changes

None. The `.raw()` method continues to accept parameterized queries and returns a QuerySet identical to the non-parameterized version, including the same failure modes (raises `DatabaseError` on syntax or execution failure). The fix preserves all existing behaviour while eliminating the injection vector.
