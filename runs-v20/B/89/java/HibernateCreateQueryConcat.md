## Verdict

Confirmed. `findByName` builds an HQL string by concatenating the caller-supplied `searchTerm` directly into the query text, then executes it via `session.createQuery()`. An attacker-controlled search term can alter the query's structure (e.g. close the `LIKE` literal and inject additional predicates or UNION clauses), so this is exploitable SQL/HQL injection.

## Source

`searchTerm`, the parameter of `ProductSearchService.findByName(String searchTerm)` (line 25) - per its Javadoc, "raw text typed into the storefront search box," i.e. untrusted end-user input with no validation or escaping applied before use.

Data flow: `searchTerm` -> concatenated into the `hql` string literal at line 27 (`"... p.name like '%" + searchTerm + "%'"`) -> passed unmodified into `session.createQuery(hql, Product.class)` at line 29 (the sink) -> `query.list()` executes it.

Sink contract:
- **Returns**: `Query<Product>` from `createQuery`, then `query.list()` returns `List<Product>` to the caller.
- **Discards**: nothing produced by the call is dropped.
- **Arguments left implicit**: none relevant - `createQuery(hql, Product.class)` only takes the query text and result type; no parameter binding is currently supplied at all.
- **Failure behaviour**: `createQuery` throws `IllegalArgumentException`/`QuerySyntaxException` on a malformed query; `query.list()` can throw `HibernateException` on execution failure. Neither is caught here - failures propagate to the caller, unchanged by the fix.

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
            query.setParameter("searchTerm", "%" + searchTerm + "%");
            return query.list();
        }
    }
}
```

## Explanation

The HQL text is now static - `searchTerm` no longer appears inside the query string, so it cannot change the query's structure. The `:searchTerm` named parameter marks a value position, and `query.setParameter("searchTerm", "%" + searchTerm + "%")` binds the whole wildcarded string as a single literal value at execution time; Hibernate sends it to the database as query-parameter data, not as parsed HQL/SQL text. Building the `%...%` wildcard around the value before binding (rather than inside the query string) keeps the "contains" search semantics identical while keeping the wildcard part of the bound literal, not the query grammar, so it cannot be used to escape out of the intended clause. `setParameter` is a standard method on `org.hibernate.query.Query`, already imported in the file, so no new dependency or import is introduced.

Difference audit against the original: the only changes are (1) the HQL literal now contains a named parameter placeholder instead of the concatenated value, and (2) one added `query.setParameter(...)` call to bind it. `query.list()`'s call, the method signature, the return type, the try-with-resources session handling, and exception propagation are all unchanged. Verification: copied the file to a scratch directory and ran `javac` on it. Compilation could not fully succeed because the Hibernate/Product classes are not on the ad hoc classpath (the same pre-existing "package does not exist" / "cannot find symbol" errors appear for `Session`, `SessionFactory`, `Query`, and `Product` as in the original file) - no new or different errors were introduced by the fix, and no error was reported on the added `setParameter` line, confirming it is syntactically well-formed. `setParameter(String, Object)` returning `Query<R>` is a documented method of `org.hibernate.query.Query` (part of `CommonQueryContract`), matching this codebase's existing Hibernate ORM usage.

## Behaviour changes

None expected. The query still selects active products whose name contains `searchTerm` (case-sensitive substring match via `LIKE '%...%'`), returns the same `List<Product>`, and propagates failures the same way. The only functional difference is that characters with HQL/SQL meaning in `searchTerm` (quotes, `%`, `_`, etc.) are now treated as literal characters of the search value instead of being interpreted as query syntax - previously a search term containing a single quote would either break the query or enable injection; now it is matched literally.
