## Verdict
exploitable

## Source
`searchTerm` parameter, String type, passed from caller as raw user input from storefront search box

## Fix
Replace string concatenation in the HQL query with Hibernate named parameters. The untrusted searchTerm is bound as a parameter value, not interpolated into the query structure.

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
The original code concatenated the untrusted `searchTerm` directly into the HQL string on line 27, creating a SQL injection sink. An attacker could inject HQL syntax such as `%' or '1'='1` to bypass the intended query logic. The fix uses Hibernate named parameters (`:searchPattern`) in the HQL string instead of concatenation. The `query.setParameter()` method treats the parameter value as data, not as executable query code. The wildcard characters are concatenated with the parameter value, but the complete value is then bound as a parameter, ensuring the untrusted input cannot modify the query structure.

## Behaviour changes
none
