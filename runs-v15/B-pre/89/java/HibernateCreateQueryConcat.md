## Verdict

Exploitable

## Source

The `searchTerm` parameter in the `findByName(String searchTerm)` method is documented as "raw text typed into the storefront search box" and is therefore attacker-controlled user input.

## Fix

**Vulnerable Code:**
```java
public List<Product> findByName(String searchTerm) {
    try (Session session = sessionFactory.openSession()) {
        String hql = "from Product p where p.active = true and p.name like '%" + searchTerm + "%'";
        // SAST FINDING: CWE-89 - SQL Injection - untrusted searchTerm concatenated into query
        Query<Product> query = session.createQuery(hql, Product.class);
        return query.list();
    }
}
```

**Fixed Code:**
```java
public List<Product> findByName(String searchTerm) {
    try (Session session = sessionFactory.openSession()) {
        String hql = "from Product p where p.active = true and p.name like :searchTerm";
        Query<Product> query = session.createQuery(hql, Product.class);
        query.setParameter("searchTerm", "%" + searchTerm + "%");
        return query.list();
    }
}
```

## Explanation

The vulnerable code constructs an HQL query by directly concatenating the user-supplied `searchTerm` into the query string on line 27. This allows an attacker to inject arbitrary HQL syntax. For example, an input like `%' or 1=1--` would transform the query into `... name like '%' or 1=1--%'`, which matches all rows regardless of the name.

The fix replaces string concatenation with Hibernate's named parameter mechanism. The HQL query now uses the placeholder `:searchTerm`, and the actual value is bound separately via `setParameter()`. This ensures the `searchTerm` value is treated as data, not as query structure. Hibernate's parameter binding handles the value safely, preventing injection. The wildcard characters (`%`) are included in the bound value as part of the `LIKE` pattern data, not as part of the query syntax.

## Behaviour changes

None. The query logic, return type, and error handling remain unchanged. The only difference is the mechanism by which the parameter is passed to the database: from string concatenation to bound parameter. The `setParameter()` call adds an explicit binding step but does not alter the query's semantics or the caller's contract.
