## Verdict

Exploitable.

## Source

User input from `searchTerm` parameter (line 25), documented as "raw text typed into the storefront search box".

## Fix

**Vulnerable code:**
```java
String hql = "from Product p where p.active = true and p.name like '%" + searchTerm + "%'";
// CWE-89: searchTerm is concatenated directly into the query string
Query<Product> query = session.createQuery(hql, Product.class);
return query.list();
```

**Fixed code:**
```java
String hql = "from Product p where p.active = true and p.name like :searchTerm";
Query<Product> query = session.createQuery(hql, Product.class);
query.setParameter("searchTerm", "%" + searchTerm + "%");
return query.list();
```

## Explanation

The vulnerability arises from concatenating untrusted user input (`searchTerm`) directly into the HQL query string. An attacker can inject HQL/SQL metacharacters to alter query logic—for example, `' or '1'='1` would bypass the name filter and return all active products regardless of the search term.

The fix replaces string concatenation with JPA named parameters. The query structure is now static (`like :searchTerm`), and `searchTerm` is passed to Hibernate's `setParameter()` method, which treats it as data only. The wildcard characters (`%`) are appended at bind time, preserving the LIKE search behaviour while preventing injection. Hibernate/JPA handles proper escaping and parameterization, ensuring `searchTerm` cannot influence query logic.

## Behaviour changes

The `setParameter()` call is added to bind the parameter value. The query now accepts `searchTerm` as a bound parameter rather than building it into the query string. Query results and return type remain unchanged.
