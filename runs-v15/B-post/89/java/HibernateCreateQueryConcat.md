## Verdict

Confirmed SQL injection. The `searchTerm` parameter is concatenated directly into an HQL query string without parameterization and passed to `session.createQuery()`, allowing attackers to inject HQL operators and manipulate query logic.

## Source

- **Input**: `searchTerm` parameter (line 25) — caller-supplied search text
- **Entry point**: Method parameter, untrusted

## Fix

Replace string concatenation with Hibernate named parameters. Use `:searchPattern` placeholder in the HQL query and bind the user input via `Query.setParameter()`:

```java
public List<Product> findByName(String searchTerm) {
    try (Session session = sessionFactory.openSession()) {
        String hql = "from Product p where p.active = true and p.name like :searchPattern";
        Query<Product> query = session.createQuery(hql, Product.class);
        query.setParameter("searchPattern", "%" + searchTerm + "%");
        return query.list();
    }
}
```

The wildcard characters (`%`) remain part of the parameter value — they are data, not SQL structure.

## Explanation

The fix replaces line 27's string concatenation with a parameterized query using Hibernate's named parameter syntax (`:searchPattern`). The `Query.setParameter()` method on line 28 binds `searchTerm` as parameter data rather than embedding it in the query string. This ensures user input is treated as a value literal, not as executable HQL. The `%` wildcards are included in the bound parameter value, so the LIKE matching operates correctly while remaining injection-safe. The method signature, return type, and functional behaviour are unchanged.

## Behaviour changes

- **Query construction**: Changed from string concatenation to parameterized query with named placeholder
- **API addition**: Added `Query.setParameter()` call to bind the search pattern
- **Query string mutation**: The HQL string now contains `:searchPattern` placeholder instead of the literal user input
- **Execution safety**: User input can no longer alter query structure or inject operators

All APIs used are standard Hibernate Query methods present in all Hibernate versions that support HQL queries.
