# AWS Lambda Vault implementation
This is example Vault implementation which can be deployed in AWS Lambda.

It should be cheap to host and allows to host `Vault` remotely.

Required services:
- AWS Lambda
- AWS API Gateway
- AWS DynamoDB

**WARNING: This `Vault` implementation stores secrets in plaintext in AWS DynamoDB**

# Setup
1. Create AWS Lambda function (runtime Python3)
2. Create DynamoDB table `vaultLastSeen` with `Partition Key`=`clientUUID`
3. Create DynamoDB table `vaultSecrets` with `Partition Key`=`clientUUID`, `Sort Key`=`secretUUID`
3. Create HTTP AWS API Gateway
4. Create below routes in AWS API Gateway:
  - GET `/api/vault/store/{client_uuid}/{secret_uuid}`
  - DELETE `/api/vault/store/{client_uuid}/{secret_uuid}`
  - POST `/api/vault/store/{client_uuid}/{secret_uuid}`
  - GET  `/api/vault/alive/{client_uuid}`
5. Attach AWS Lambda integration to each route. All routes should be integrated with same AWS Lambda function.
6. In AWS IAM, find role used by our AWS Lambda and click `Add permissions` -> `Create inline policy`
```
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "AllowCRUDOperationsOnVault",
			"Effect": "Allow",
			"Action": [
				"dynamodb:GetItem",
				"dynamodb:PutItem",
				"dynamodb:DeleteItem"
			],
			"Resource": [
				"arn:aws:dynamodb:${region}:${account-id}:table/vaultLastSeen",
				"arn:aws:dynamodb:${region}:${account-id}:table/vaultSecrets"
			]
		}
	]
}
```
7. Generate bearer token for `DMH` -> `Vault` communication
```
dmh-cli auth generate-bearer
```
8. Configure `CONFIG` dict in `lambda-vault.py`:
  - `process_unit` - time unit (`minute`, `hour`) used to decide when secret should be released. It should match `action.process_unit` from `DMH` config.
  - `auth.bearer.token` - put generated token `hash` and set token `scope` to your `remote_vault.client_uuid` (`api:vault:store:<client_uuid>`, `api:vault:alive:<client_uuid>`). Scopes work same as in `DMH`.
  - Authentication can be disabled with `auth.enabled: False`. THIS IS NOT RECOMMENDED FOR SECURITY REASONS!
9. Set in `DMH` config file AWS Lambda `Vault` address and generated token plaintext
```
remote_vault:
  url: https://${api-gateway-id}.execute-api.${aws-region}.amazonaws.com/default
  client_uuid: <client_uuid>
  token: <generated-bearer-token>
```
