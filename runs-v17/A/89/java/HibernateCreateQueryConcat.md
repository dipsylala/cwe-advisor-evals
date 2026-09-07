## Verdict
Confirmed SQL Injection vulnerability via unsafe HQL string concatenation.

## Source
Line 27 constructs an HQL query by concatenating the caller-supplied `searchTerm` directly into the query string without parameterization. Line 29 passes this unsanitized query to `session.createQuery()`, making it the taint sink.

An attacker can inject HQL metacharacters through the search box. For example, a `searchTerm` of `' or '1'='1` transforms the query to:
```
from Product p where p.active = true and p.name like '%' or '1'='1%'
```
This bypasses the `active = true` filter, disclosing all products regardless of status.

## Fix

### File: ProductSearchService.java
```java
package com.example.catalog;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.query.Query;

import java.util.List;

/**
 * Backs the product catalog's free-text search box.
 */
public class ProductSearchService {

    private final SessionFactory sessionFactory;

    public ProductSearchService(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    /**
     * Returns active products whose name contains the caller-supplied search term.
     *
     * @param searchTerm raw text typed into the storefront search box
     */
    public List<Product> findByName(String searchTerm) {
        try (Session session = sessionFactory.openSession()) {
            String hql = "from Product p where p.active = true and p.name like :searchPattern";
            Query<Product> query = session.createQuery(hql, Product.class);
            query.setParameter("searchPattern", "%" + searchTerm + "%");
            return query.list();
        }
    }
}
```

## Explanation
Replace string concatenation with parameterized queries using Hibernate's `setParameter()` method with named parameters. The `:searchPattern` placeholder in the HQL is bound to the actual value via `setParameter()`, ensuring the database driver escapes any special characters in `searchTerm`. This prevents the attacker-supplied string from being interpreted as HQL syntax. The wildcard characters `%` remain part of the pattern value itself, not injected into the query structure.
