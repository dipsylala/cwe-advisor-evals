from report_store import open_report


def download_report(request):
    report_path = request.args.get("path", "")
    handle = open_report(report_path)
    return request.send_file(handle, download_name=report_path.rsplit("/", 1)[-1])
