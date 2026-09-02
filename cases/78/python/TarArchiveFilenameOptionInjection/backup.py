import subprocess


def create_backup_archive(archive_path, filenames):
    command = ["tar", "czf", archive_path]
    command.extend(filenames)

    # SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
    subprocess.run(command, shell=False, check=True)
