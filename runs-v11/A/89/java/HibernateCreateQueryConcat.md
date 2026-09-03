## Verdict
Confirmed SQL injection via string concatenation into HQL query.

## Source
Line 27 concatenates caller-supplied `searchTerm` directly into the HQL string without parameterization, then line 29 executes the query. An attacker can inject HQL fragments to alter query logic or extract data.

## Fix
Replace string concatenation with parameterized query binding:

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

The pattern `"%" + searchTerm + "%"` is safe to concatenate here because it is constructed only from the literal `"%"` characters and the untrusted `searchTerm`. The actual user input is passed as a bound parameter `:searchPattern`, which Hibernate treats as data rather than code.

## Explanation
String concatenation into HQL queries treats user input as part of the query structure. Parameterized queries use named parameters (`:paramName`) as placeholders; the value is passed separately via `setParameter()` and the database driver escapes it as literal data, not executable code. This prevents an attacker from injecting HQL operators, keywords, or logic by embedding quotes, `or`, comments, or other syntax in the input.
