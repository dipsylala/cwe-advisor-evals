import os

REPORT_ROOT = os.path.abspath("/srv/app/reports")


def open_report(relative_path):
    candidate = os.path.abspath(os.path.join(REPORT_ROOT, relative_path))
    if not candidate.startswith(REPORT_ROOT):
        raise PermissionError("report path escapes root")

    return open(candidate, "rb")
