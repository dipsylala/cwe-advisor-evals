## Verdict

Confirmed. `findByName` builds an HQL query string by concatenating the caller-supplied `searchTerm` directly into a `like` clause and passes it to `session.createQuery(hql, Product.class)`. An attacker-controlled search term can break out of the intended string literal (e.g. via an embedded `'`) and alter the query's logic or structure, which is HQL injection (CWE-89).

## Source

`searchTerm`, the parameter to `ProductSearchService.findByName(String searchTerm)` (line 25), documented as "raw text typed into the storefront search box" - untrusted, attacker-controlled input from the product catalog's free-text search box.

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
            String hql = "from Product p where p.active = true and p.name like :searchTerm";
            Query<Product> query = session.createQuery(hql, Product.class);
            query.setParameter("searchTerm", "%" + escapeLikeWildcards(searchTerm) + "%");
            return query.list();
        }
    }

    /**
     * Escapes Hibernate's default LIKE wildcard characters ('%', '_') and the
     * escape character itself so the search term is matched literally; only the
     * '%' wildcards this method adds around the term remain active.
     */
    private static String escapeLikeWildcards(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_");
    }
}
```

## Explanation

The vulnerable code built the HQL string by directly concatenating `searchTerm` between single quotes (`'%" + searchTerm + "%'`). A search term containing a `'` terminates the string literal early, letting an attacker inject arbitrary HQL - altering the `where` clause, exfiltrating data from other entities via subqueries, or bypassing the `p.active = true` restriction entirely.

The fix replaces the concatenated literal with a named parameter (`:searchTerm`) and binds the value via `query.setParameter(...)`. Hibernate sends parameterized queries to the database using bind variables, so the value is never parsed as part of the HQL/SQL grammar - it is always treated as a single literal value, regardless of its content. This is the primary defence and fully closes the injection.

A secondary, non-security concern is preserved correctness: because the `%` wildcards are now added in application code around the bound value rather than inside a literal, the search term itself could contain `%` or `_` characters that Hibernate's `like` operator would otherwise interpret as wildcards (Hibernate's default LIKE escape character is `\`). `escapeLikeWildcards` neutralizes those so a literal `%` or `_` typed by the user matches literally instead of acting as a wildcard, keeping search behavior consistent with before the fix. This escaping is a correctness/behavior-preservation step, not the security fix - parameter binding alone eliminates the SQL/HQL injection.

Verification: exercise `findByName` with a term such as `foo' or '1'='1` and confirm it now searches for that literal string (matching zero products) rather than altering query semantics; also confirm a term with a literal `%` (e.g. `50%`) still matches only products containing `50%`, not all products.
