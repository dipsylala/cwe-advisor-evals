from customer_service import search_customers


def customer_search_endpoint(request):
    tenant_id = request.user.tenant_id
    term = request.GET.get("q", "")
    field = request.GET.get("field", "name")
    return {"customers": list(search_customers(tenant_id, term, field))}
