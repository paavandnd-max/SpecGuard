"""S3 report-store scaffold.

No AWS client is constructed here. The application must supply an approved,
configured storage implementation before any report is uploaded.
"""


class S3ReportStore:
    def __init__(self, bucket: str | None = None):
        self.bucket = bucket

    def upload(self, report_path: str, key: str) -> None:
        raise RuntimeError(
            "S3ReportStore is a scaffold; configure credentials and an approved "
            "AWS client before uploading reports."
        )
