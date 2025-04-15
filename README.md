![dead-man-hand-logo](https://github.com/user-attachments/assets/0a0e041a-e76b-471a-9b05-14288a7325cb)

# Idea
Dead-Man-Hand will execute pre-added actions when you will no longer be "available".

**All actions are encrypted and when properly configured nobody will be able to get action details till you are alive.**

Main goal of `DMH` is to ensure that actions can be executed only when you are dead. And before that time, every action should be confidential - even for people who have access to `DMH`.

# Features
- Privacy focused - even with access to `DMH` you will not be able to see action details.
- Tested - almost 100% code covered by unit tests and integration tests.
- Small footprint
- Multiple action execution methods (`json_post`, `bulksms`, `mail`)
- Multiple alive probe methods (`json_post`, `bulksms`, `mail`)

# How it works
<img width="1023" alt="dmh-flow" src="https://github.com/user-attachments/assets/63a5a1a9-c692-4ade-a971-073b807653fe" />

1. User creates action
2. DMH encrypt action with [age](https://github.com/FiloSottile/age)
3. DMH uploads encryption private key to Vault
4. Vault encrypts private key with own key and saves it (Vault will `release` encryption private key when user will be considered dead)
5. DMH saves encrypted action, discards plaintext action, discards private key (**from now, nobody is able to see unencrypted action, even DMH**)
6. DMH will sent alive probes to user
7. When user will ignore N probes (configured per action), she/he would be considered dead.
8. When both DMH and Vault will decide that user is dead, Vault secrets will be released, actions would be decrypted and executed.
9. After execution, DMH will remove encryption private key from Vault - to ensure that action will remain confidential


**To decrypt action, access to `DMH` and `Vault` is required - `DMH` stores encrypted data and `Vault` stores encryption key.**

**To provide best possible privacy/security, its required to run `DMH` and `Vault` on different systems/servers/locations.**

## DMH
`DMH` is main component which implements whole logic.

It is responsible for:
- Storing encrypted actions
- Uploading private encryption keys to Vault
- Get private encryption keys from Vault
- Delete private encryption keys from Vault (when action was executed)
- Executing actions
- Updating Vault information when user was last seen

`DMH` will try to execute action when user was `LastSeen` `ProcessAfter` number of hours ago. Each action can heave different `ProcessAfter`.

Till `Vault` will not `release` private key, **action will not be executed, as its stored in encrypted form!**

### API
```
/api/alive - updates `DMH` and `Vault` `LastSeen`
/api/action/test - perform action test
/api/action/store - create, list action(s)
/api/action/store/{actionUUID} - get, delete action
```

## Vault
`Vault` is very simple encrypted data store. 

It is responsible for:
- Storing encrypted private keys

To ensure private keys can be fetched only when user is considered dead, `Vault` have own `LastSeen` information and its not depending on `DMH` `LastSeen`.

`Vault` can be also hosted as AWS Lambda (TBD).

Vault will `release` secret when user was `LastSeen` `ProcessAfter` number of hours ago. Each action have unique secret, each secret can have different `ProcessAfter`.

Only `released` secrets can be fetched/deleted.

### API
```
/api/vault/alive/{clientUUID} - updates `Vault` `LastSeen` for a client (`DMH` instance)
/api/vault/store/{clientUUID}/{secretUUID} - create, get, delete vault secret
```

# Execute plugins

## dummy
Dummy plugin can be used for tests. It will just log user message during execution.

### Payload
```
{
  "message": "some message"
}
```

## json_post
Json_post plugin will send `HTTP` `POST` request with `application/json` content-type. It can be used to interact with external systems (remove data, post some blog article, etc).

### Payload
```
{
  "url": "https://some-address.com",
  "headers": {
    "header1": "value1",
    "header2": "value2"
  },
  "data": {
    "action": "delete-isos",
    "token": "very-secret-token",
    "timeout": 3600
  },
  "success_code": [
    200
  ]
}
```

## mail
Mail plugin will send mail over `SMTP` protocol.

### Config
```
execute:
  plugin:
    mail:
      username: "username"
      password: "password"
      server: "smtp.server.com"
      from: "from@address.com"
      tls_policy: tls_mandatory
```

### Payload
```
{
  "message": "some message",
  "destination": [
    "address@one.com",
    "address2@two.com"
  ],
  "subject": "mail subject"
}
```

## bulksms
BulkSMS plugin will send SMS with [bulksms](https://bulksms.com) HTTP API.

### Config
```
execute:
  plugin:
    bulksms:
      routing_group: standard
      token:
        id: "bulksms-auth-token-id"
        secret: "bulksms-auth-token-secret"
```

### Payload
```
{
  "message": "some message",
  "destination": [
    "+4812345",
    "+1123456"
  ]
}
```
# Config
```
# running vault and dmh together is not recomendated, please use this only for tests.
components:
  - vault
  - dmh
vault:
  # key used to encrypt vault data at-rest - `age-keygen` to generate new private key
  key: AGE-SECRET-KEY-1DM8K50X86KHCPQ3PPZ52PVLJLMGDCGMA0WMGD406SGLJ2JAN7R4S2GLM6W
  file: vault.json # where to save vault data
state:
  file: state.json # where to save dmh data
# each alive probe can use any of execute plugins
alive:
  - every: 24 # execute this probe every 24 hours
    kind: mail
    data:
      message: Are you still alive? Please confirm by clicking https://dmh-domain:8080/api/alive
      subject: Still ok?
      destinaton:
        - owner@domain.com
  - every: 36 # execute this probe every 36 hours
    kind: bulksms
    data:
      message: Are you ok? Please click https://dmh-domain:8080/api/alive
      destination:
        - +48123456678
        - +48987654321
# address to vault
remote_vault:
  client_uuid: random-uuid-dont-copy # generate new, random, UUID
  url: http://127.0.0.1:8080
# configuration for all execute plugins
execute:
  plugin:
    bulksms:
      routing_group: premium
      token:
        id: "auth-token-id"
        secret: "auth-token-secret"
    mail:
      username: "username"
      password: "password"
      server: smtp.server.com
      from: dmh@some-domain.com
      tls_policy: tls_mandatory
```

# CLI

## alive subcommand
Update `DMH` and `Vault` `LastSeen` information
```
% dmh-cli alive update
```

## action subcommand
### add
Add new action to `DMH`, `data` parameter will be encrypted. 
```
% dmh-cli action add --comment comment --kind bulksms --process-after 10 --data '{"message": "some secret message", "destination": ["+48123"]}'
Action added successfully
```
### list / ls
List all stored actions from `DMH`.
```
% dmh-cli action ls | jq
[
  {
    "kind": "bulksms",
    "process_after": 10,
    "comment": "comment",
    "data": "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBqeVVXWmN2c0kxVFlycWdlcjhOQWtRN24vS0JqUFdjZ3pseW9kdDkxbldNCmd1Q1hjejVEaWJpL1hVU25rTC81MkRQcDEyY3JVbjg1OEJNRjRsaHgxdTAKLS0tIE5BaWNWT0k0SHN4Y0dUeWVWTHdlMEhMc0xVU2gwUkVPT0FvTGhvb3FCdG8KISgQKJJ+m+7oCy8V7RlSFARNYUOzBbGVmd92wdxZA71k3PoIxpXopKfY5vnTNlGj2cVnXuSYe3BJOLSM5GCAOQwDt4QXlIheQSVu5FHS",
    "uuid": "b9a95651-2cd6-4d73-9b95-eed96c151174",
    "processed": 0,
    "encryption": {
      "kind": "X25519",
      "vault_url": "http://127.0.0.1:8080/api/vault/store/random-uuid-dont-copy/b9a95651-2cd6-4d73-9b95-eed96c151174"
    }
  }
]
```
### delete
Delete action from `DMH`
```
 % dmh-cli action delete --uuid b9a95651-2cd6-4d73-9b95-eed96c151174
Action deleted successfully
```
### test
Perform action test. 

**THIS IS RECOMENDATED BEFORE USING `action add`, TO CONFIRM THAT PROVIDED `data` is OK.**
```
% dmh-cli action test --kind dummy --data '{"message": "test"}'
Action tested successfully
```
