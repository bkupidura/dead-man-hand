import json
import boto3
import time
import re

dynamodb_client = boto3.resource("dynamodb")
last_seen_table = dynamodb_client.Table("vaultLastSeen")
secrets_table = dynamodb_client.Table("vaultSecrets")

process_after_unit = 60 * 60


def http_not_found():
    return {"statusCode": 404, "body": "Not Found"}


def http_locked():
    return {"statusCode": 423, "body": "Locked"}


def http_ok(data):
    return {"statusCode": 200, "body": json.dumps(data)}


def http_created():
    return {"statusCode": 201, "body": json.dumps("Created")}


def lambda_handler(event, context):
    reqCtxHttp = event.get("requestContext", dict()).get("http", dict())

    searcher = re.search(".+?/api/vault/(.+?)/", reqCtxHttp.get("path"))
    endpoint = searcher.group(1)

    if endpoint not in ["alive", "store"]:
        return http_not_found()

    client_uuid = event.get("pathParameters", dict()).get("client_uuid")
    if client_uuid is None or len(client_uuid) == 0:
        return http_not_found()

    now = int(time.time())

    if endpoint == "alive":
        last_seen_table.put_item(Item={"clientUUID": client_uuid, "lastSeen": now})
        return http_ok("OK")

    if endpoint == "store":
        secret_uuid = event.get("pathParameters", dict()).get("secret_uuid")
        if secret_uuid is None or len(secret_uuid) == 0:
            return http_not_found()

        last_seen = (
            last_seen_table.get_item(Key={"clientUUID": client_uuid})
            .get("Item", {})
            .get("lastSeen", now)
        )
        secret = secrets_table.get_item(
            Key={"clientUUID": client_uuid, "secretUUID": secret_uuid}
        ).get("Item")

        method = reqCtxHttp.get("method")

        if method in ["GET", "DELETE"]:
            if secret is None:
                return http_not_found()

            if now - last_seen <= secret["processAfter"] * process_after_unit:
                return http_locked()

            if method == "GET":
                return http_ok(
                    {
                        "key": secret["key"],
                        "process_after": int(secret["processAfter"]),
                    },
                )
            if method == "DELETE":
                secrets_table.delete_item(
                    Key={"clientUUID": client_uuid, "secretUUID": secret_uuid}
                )
                return http_ok("OK")

        if method == "POST":
            if secret is not None:
                return http_not_found()

            try:
                request_data = json.loads(event.get("body"))
            except:
                return http_not_found()

            if "key" not in request_data or "process_after" not in request_data:
                return http_not_found()

            secrets_table.put_item(
                Item={
                    "clientUUID": client_uuid,
                    "secretUUID": secret_uuid,
                    "key": request_data["key"],
                    "processAfter": request_data["process_after"],
                }
            )

            return http_created()
