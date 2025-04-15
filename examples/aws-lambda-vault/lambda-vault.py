import json
import boto3
import time
import re

s3_client = boto3.client("s3")
bucket_name = "dmh-vault"
state_name = "state.json"
process_after_unit = 60 * 60


def http_not_found():
    return {"statusCode": 404, "body": "Not Found"}


def http_ok(state, data):
    s3_client.put_object(Bucket=bucket_name, Key=state_name, Body=json.dumps(state))

    return {"statusCode": 200, "body": json.dumps(data)}


def http_created(state):
    s3_client.put_object(Bucket=bucket_name, Key=state_name, Body=json.dumps(state))

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

    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=state_name)
        state = json.loads(response["Body"].read().decode("utf-8"))
    except:
        state = {"vault": dict()}

    now = int(time.time())

    if client_uuid not in state["vault"]:
        state["vault"][client_uuid] = {"last_seen": now, "secrets": dict()}

    if endpoint == "alive":
        state["vault"][client_uuid]["last_seen"] = now
        return http_ok(state, "OK")

    if endpoint == "store":
        secret_uuid = event.get("pathParameters", dict()).get("secret_uuid")
        if secret_uuid is None or len(secret_uuid) == 0:
            return http_not_found()

        last_seen = state["vault"][client_uuid]["last_seen"]
        method = reqCtxHttp.get("method")

        if method in ["GET", "DELETE"]:
            if secret_uuid not in state["vault"][client_uuid]["secrets"]:
                return http_not_found()

            vault_data = state["vault"][client_uuid]["secrets"][secret_uuid]
            if now - last_seen <= vault_data["process_after"] * process_after_unit:
                return http_not_found()

            if method == "GET":
                return http_ok(state, vault_data)
            if method == "DELETE":
                del state["vault"][client_uuid]["secrets"][secret_uuid]
                return http_ok(state, "OK")

        if method == "POST":
            if secret_uuid in state["vault"][client_uuid]["secrets"]:
                return http_not_found()

            try:
                request_data = json.loads(event.get("body"))
            except:
                return http_not_found()

            if "key" not in request_data or "process_after" not in request_data:
                return http_not_found()

            state["vault"][client_uuid]["secrets"][secret_uuid] = {
                "key": request_data["key"],
                "process_after": request_data["process_after"],
            }
            return http_created(state)
