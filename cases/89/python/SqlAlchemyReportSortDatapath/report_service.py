from report_repository import fetch_report_rows


def run_report(session, account_id, status, sort):
    return fetch_report_rows(session, account_id, status, sort)
