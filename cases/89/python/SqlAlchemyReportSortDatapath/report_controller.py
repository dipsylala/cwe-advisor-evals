from report_service import run_report


def report_endpoint(request, session):
    account_id = request.user.account_id
    status = request.args.get("status", "open")
    sort = request.args.get("sort", "created_at")
    rows = run_report(session, account_id, status, sort)
    return {"rows": [dict(row) for row in rows]}
