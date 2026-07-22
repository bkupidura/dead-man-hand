import hashlib
import hmac
import json
import re
import time

import boto3

dynamodb_client = boto3.resource("dynamodb")
last_seen_table = dynamodb_client.Table("vaultLastSeen")
secrets_table = dynamodb_client.Table("vaultSecrets")

# CONFIG mirrors DMH vault config.
# process_unit is time unit used to decide when secret should be released (minute, hour).
# auth mirrors DMH auth config - hash is hex encoded sha256 of token plaintext,
# generated with dmh-cli auth generate-bearer.
CONFIG = {
    "process_unit": "hour",
    "auth": {
        "enabled": True,
        "anonymous_scope": [],
        "bearer": {
            "token": [
                {
                    "name": "dmh-main",
                    "hash": "PUT-SHA256-TOKEN-HASH-HERE",
                    "scope": [
                        "api:vault:store:PUT-CLIENT-UUID-HERE",
                        "api:vault:alive:PUT-CLIENT-UUID-HERE",
                    ],
                },
            ],
        },
    },
}

PROCESS_UNITS = {"minute": 60, "hour": 60 * 60}


def http_not_found():
    return {"statusCode": 404, "body": "Not Found"}


def http_locked():
    return {"statusCode": 423, "body": "Locked"}


def http_unauthorized():
    return {
        "statusCode": 401,
        "headers": {"WWW-Authenticate": 'Bearer realm="dmh"'},
        "body": "Unauthorized",
    }


def http_ok(data):
    return {"statusCode": 200, "body": json.dumps(data)}


def http_created():
    return {"statusCode": 201, "body": json.dumps("Created")}


def bearer_from_header(event):
    headers = event.get("headers") or {}
    auth_header = headers.get("authorization", "")
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


def token_scopes(presented):
    if not presented:
        return None
    presented_hash = hashlib.sha256(presented.encode()).hexdigest()
    for token in CONFIG["auth"]["bearer"]["token"]:
        if hmac.compare_digest(presented_hash, token["hash"].lower()):
            return token["scope"]
    return None


def scope_covers(scope, path_segments):
    segments = scope.split(":")
    if len(segments) > len(path_segments):
        return False
    return all(a == b for a, b in zip(segments, path_segments))


def any_scope_covers(scopes, path_segments):
    return any(scope_covers(scope, path_segments) for scope in scopes)


def authorized(event, path_segments):
    auth = CONFIG["auth"]
    if not auth.get("enabled", True):
        return True
    if any_scope_covers(auth.get("anonymous_scope", []), path_segments):
        return True
    scopes = token_scopes(bearer_from_header(event))
    if scopes is not None and any_scope_covers(scopes, path_segments):
        return True
    return False


def lambda_handler(event, context):
    reqCtxHttp = event.get("requestContext", dict()).get("http", dict())

    searcher = re.search(".+?/api/vault/(.+?)/", reqCtxHttp.get("path"))
    endpoint = searcher.group(1)

    if endpoint not in ["alive", "store"]:
        return http_not_found()

    client_uuid = event.get("pathParameters", dict()).get("client_uuid")
    if client_uuid is None or len(client_uuid) == 0:
        return http_not_found()

    path_segments = ["api", "vault", endpoint, client_uuid]

    secret_uuid = None
    if endpoint == "store":
        secret_uuid = event.get("pathParameters", dict()).get("secret_uuid")
        if secret_uuid is None or len(secret_uuid) == 0:
            return http_not_found()
        path_segments.append(secret_uuid)

    if not authorized(event, path_segments):
        return http_unauthorized()

    now = int(time.time())
    process_unit = PROCESS_UNITS.get(CONFIG["process_unit"], PROCESS_UNITS["hour"])

    if endpoint == "alive":
        last_seen_table.put_item(Item={"clientUUID": client_uuid, "lastSeen": now})
        return http_ok("OK")

    if endpoint == "store":
        last_seen = (
            last_seen_table.get_item(Key={"clientUUID": client_uuid})
            .get("Item", {})
            .get("lastSeen", now)
        )
        secret = secrets_table.get_item(
            Key={"clientUUID": client_uuid, "secretUUID": secret_uuid}
        ).get("Item")

        method = reqCtxHttp.get("method")

        if method in ["GET", "HEAD", "DELETE"]:
            if secret is None:
                return http_not_found()

            if now - last_seen <= secret["processAfter"] * process_unit:
                return http_locked()

            if method == "HEAD":
                return http_ok("OK")
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
