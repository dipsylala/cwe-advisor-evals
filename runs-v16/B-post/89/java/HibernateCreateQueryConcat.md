## Verdict
Exploitable

## Source
`searchTerm` parameter (line 25), described as "raw text typed into the storefront search box" - user-controlled, attacker-supplied input.

## Fix
**Vulnerable code (line 27-29):**
```java
String hql = "from Product p where p.active = true and p.name like '%" + searchTerm + "%'";
Query<Product> query = session.createQuery(hql, Product.class);
return query.list();
```

**Fixed code:**
```java
String hql = "from Product p where p.active = true and p.name like :searchTerm";
Query<Product> query = session.createQuery(hql, Product.class);
query.setParameter("searchTerm", "%" + searchTerm + "%");
return query.list();
```

## Explanation
The vulnerability was caused by string concatenation of untrusted `searchTerm` directly into the HQL query string, allowing an attacker to manipulate query logic (e.g., `%' or '1'='1` breaks out of the quoted context). The fix replaces this with Hibernate's parameterized query mechanism: a named parameter placeholder (`:searchTerm`) in the HQL string, with the actual value bound separately via `query.setParameter()`. This ensures `searchTerm` is always treated as data, not as executable query structure. The wildcard characters (`%`) remain safe because they are part of the literal pattern value being bound, not the query structure. An attacker-supplied payload like `%' or '1'='1` will be bound as a literal string pattern and will not manipulate the query logic.

## Behaviour changes
None. The query executes the same logical operation (active products with names matching the search term using SQL LIKE), returns the same `List<Product>`, and throws the same checked exceptions. The `setParameter()` method returns the `Query` object itself, so the fluent chain continues without alteration. `setParameter()` and subsequent `list()` execute before the method returns, preserving the original control flow and exception handling.
