# HibernateCreateQueryConcat

## Verdict

**CONFIRMED**: SQL Injection via Hibernate query string concatenation (CWE-89)

The `searchTerm` parameter is concatenated directly into the HQL string at line 27 without parameterization. An attacker can inject HQL syntax to manipulate the query logic—for example, `searchTerm = "%' OR '1'='1"` would bypass the `p.active = true` condition, exposing inactive products.

## Source

**File**: ProductSearchService.java  
**Line**: 27–29  
**Vulnerable pattern**: String concatenation of untrusted user input into HQL query  
**Source**: `searchTerm` parameter (marked as raw text from the storefront search box)  
**Sink**: `session.createQuery(hql, Product.class)` at line 29  

**Data flow**:
```
searchTerm (user input) 
  → line 27: "from Product p where p.active = true and p.name like '%" + searchTerm + "%'"
  → line 29: session.createQuery(hql, Product.class)
```

The HQL string is fully formed before being passed to `createQuery()`, so the injection has already occurred by the time the query object is instantiated.

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

The fix replaces string concatenation with Hibernate's named parameter mechanism:

1. **HQL string** (line 27): Changed from concatenated `"... like '%" + searchTerm + "%'"` to parameterized `"... like :searchPattern"`. The HQL now contains a placeholder (`:searchPattern`) instead of a literal value.

2. **Parameter binding** (line 28–29, new): After creating the query object, `query.setParameter("searchPattern", "%" + searchTerm + "%")` binds the user-supplied `searchTerm` as a parameter value. The Hibernate driver treats this value as data, not as executable HQL syntax, preventing injection.

3. **Wildcard pattern construction**: The LIKE pattern (`"%" + searchTerm + "%"`) is constructed in Java before being passed to `setParameter()`. This is safe because the `%` wildcards are fixed literals, and `searchTerm` is bound as a string value—any special characters (quotes, backslashes, etc.) are escaped by the driver.

The query logic remains identical: it still returns active products whose name contains the search term, but the injection vector is closed because the untrusted input never touches the HQL syntax tree.

## Behaviour changes

- **Query execution**: The query still executes the same SQL logic (select active products matching the search term), so application behavior is unchanged.
- **Performance**: Negligible—parameter binding is the standard Hibernate execution path.
- **Error handling**: No change—`createQuery()` and `list()` throw the same exceptions on database errors.
- **Return type**: Unchanged—`List<Product>` is returned as before.
- **Input handling**: Special characters in `searchTerm` (quotes, backslashes, SQL keywords) are now safely escaped by the driver instead of being interpreted as part of the HQL syntax. For example, `searchTerm = "O'Brien"` now correctly searches for products named "O'Brien" instead of breaking the query.
