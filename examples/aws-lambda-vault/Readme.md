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
7. Set in `DMH` config file AWS Lambda `Vault` address
```
remote_vault:
  url: https://${api-gateway-id}.execute-api.${aws-region}.amazonaws.com/default
```
