# AWS Lambda Vault implementation
This is example Vault implementation which can be deployed in AWS Lambda.

It should be cheap to host and allows to host `Vault` remotely.

Required services:
- AWS Lambda
- AWS API Gateway
- AWS S3

**WARNING: This `Vault` implementation stores secrets in plaintext in AWS S3 bucket.**

# Setup
1. Create AWS Lambda function (runtime Python3)
2. Create AWS S3 bucket, **without** public access with `Bucket policy`
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowGetObjectAndPutObjectForSpecificRole",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:sts::826118986860:assumed-role/${lambda-assumed-role}/dmh-vault"
            },
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::${bucket-name}/state.json"
        }
    ]
}
```
3. Create HTTP AWS API Gateway
4. Create below routes:
  - GET `/api/vault/store/{client_uuid}/{secret_uuid}`
  - DELETE `/api/vault/store/{client_uuid}/{secret_uuid}`
  - POST `/api/vault/store/{client_uuid}/{secret_uuid}`
  - GET  `/api/vault/alive/{client_uuid}`
5. Attach AWS Lambda integration to each route. All routes should be integrated with same AWS Lambda function.
6. Set proper AWS S3 bucket name in AWS Lambda (`bucket_name` variable)
7. Set in `DMH` config file AWS Lambda `Vault` address
```
remote_vault:
  url: https://${api-gateway-id}.execute-api.${aws-region}.amazonaws.com/default
```
