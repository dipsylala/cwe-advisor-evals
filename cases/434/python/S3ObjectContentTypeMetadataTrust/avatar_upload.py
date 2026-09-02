import boto3

s3 = boto3.client("s3")


def upload_avatar(bucket, key, file_bytes, content_type):
    # SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    s3.put_object(Bucket=bucket, Key=key, Body=file_bytes, ContentType=content_type)
