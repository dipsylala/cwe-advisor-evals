## Verdict
CONFIRMED

## Source
Line 27: `String hql = "from Product p where p.active = true and p.name like '%" + searchTerm + "%'";`

The `searchTerm` parameter is concatenated directly into the HQL query string without parameterization, allowing an attacker to inject arbitrary HQL/SQL fragments (e.g., `%' or 1=1 or '%'`) that alter query logic or exfiltrate data.

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
The fix uses a named parameter (`:searchPattern`) in the HQL query and binds the value via `setParameter()`. This ensures the user-supplied `searchTerm` is treated as a data value, not as part of the query syntax. The wildcard pattern `%...%` is applied to the parameter value, not injected into the query string, preventing HQL/SQL injection.
