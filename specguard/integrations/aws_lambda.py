"""AWS Lambda entrypoint scaffold; deployment is intentionally out of scope."""

import json


def handler(event, context):
    return {"statusCode": 501, "body": json.dumps({"message": "SpecGuard Lambda scaffold; configure a local project input."})}
