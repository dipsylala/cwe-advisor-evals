"""Windows report export service.

Runs a bundled .bat script (export_report.bat) that wraps the legacy
reporting toolchain used on the deployment host. The script accepts a
report identifier and writes the rendered report to the shared output
folder.
"""

import os
import subprocess

SCRIPTS_DIR = r"C:\ReportingService\scripts"
OUTPUT_DIR = r"C:\ReportingService\output"


def export_report(report_id: str) -> str:
    """Invoke the bundled export_report.bat for the given report id.

    report_id is supplied by the caller (e.g. taken from a web request
    query parameter) and is expected to be a short alphanumeric report
    key, but no validation is performed before it reaches the shell.
    """
    bat_path = os.path.join(SCRIPTS_DIR, "export_report.bat")
    output_path = os.path.join(OUTPUT_DIR, report_id + ".pdf")

    command = bat_path + " " + report_id + " " + output_path

    # SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        raise RuntimeError(f"export_report.bat failed: {stderr.decode(errors='replace')}")

    return output_path
