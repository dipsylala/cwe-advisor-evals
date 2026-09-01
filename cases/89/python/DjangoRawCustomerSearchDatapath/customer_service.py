from customer_repository import raw_customer_search


def search_customers(tenant_id, term, field):
    return raw_customer_search(tenant_id, term, field)
