## Verdict
Real SQL injection vulnerability. The `searchTerm` parameter is directly concatenated into the HQL query string without sanitization or parameterization, allowing an attacker to inject arbitrary HQL code.

## Source
```java
String hql = "from Product p where p.active = true and p.name like '%" + searchTerm + "%'";
Query<Product> query = session.createQuery(hql, Product.class);
```

Line 27 concatenates the user-supplied `searchTerm` directly into the HQL query string.

## Fix
Use Hibernate's parameterized query mechanism with named or positional parameters:

```java
public List<Product> findByName(String searchTerm) {
    try (Session session = sessionFactory.openSession()) {
        String hql = "from Product p where p.active = true and p.name like :searchPattern";
        Query<Product> query = session.createQuery(hql, Product.class)
            .setParameter("searchPattern", "%" + searchTerm + "%");
        return query.list();
    }
}
```

## Explanation
String concatenation directly embeds user input into the query, allowing attackers to manipulate the query structure. An attacker can inject characters like `'` or `--` to break out of the intended SQL context and execute unintended operations. Parameterized queries (using `setParameter()`) separate the query structure from the data values—the database driver treats the parameter value purely as data, never as executable code, regardless of its content. This eliminates the syntax-injection attack vector entirely.
