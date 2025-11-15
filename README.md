![dead-man-hand-logo](https://github.com/user-attachments/assets/0a0e041a-e76b-471a-9b05-14288a7325cb)

# Idea
Dead-Man-Hand will execute pre-added actions when you will no longer be "available".

**All actions are encrypted and when properly configured nobody will be able to get action details until you are dead.**

Main goal of `DMH` is to ensure that actions can be executed only when you are dead. And before that time, every action should be confidential - even for people who have access to `DMH`.

# Features
- Privacy focused - even with access to `DMH` you will not be able to see action details.
- Tested - almost 100% code covered by unit tests and integration tests.
- Small footprint (less than 20MB of RAM needed)
- Multiple action execution methods (`json_post`, `bulksms`, `mail`)

# How it works
<img width="1023" alt="dmh-flow" src="https://github.com/user-attachments/assets/63a5a1a9-c692-4ade-a971-073b807653fe" />

1. User creates action
2. DMH encrypts action with [age](https://github.com/FiloSottile/age)
3. DMH uploads encryption private key to Vault
4. Vault encrypts private key with own key and saves it (Vault will `release` encryption private key when user will be considered dead)
5. DMH saves encrypted action, discards plaintext action, discards private key (**from now, nobody is able to see unencrypted action, even DMH**)
6. When user will not be available for some time (configured per action), she/he would be considered dead.
7. When both DMH and Vault will decide that user is dead, Vault secrets will be released, actions would be decrypted and executed.
8. After execution, DMH will remove encryption private key from Vault - to ensure that action will remain confidential (only valid for actions with `min_interval: 0`).


**To decrypt action, access to `DMH` and `Vault` is required - `DMH` stores encrypted data and `Vault` stores encryption key.**

**To provide best possible privacy/security, its required to run `DMH` and `Vault` on different systems/servers/locations.**

# Installation

## Docker (recommended)
```
docker run --name dead-man-hand -e DMH_CONFIG_FILE=/data/config.yaml -v /srv/dead-man-hand/data:/data -p 8080:8080 ghcr.io/bkupidura/dead-man-hand:latest
```

## Baremetal
1. Install `golang`
2. Clone repo: `git clone https://github.com/bkupidura/dead-man-hand.git`
3. Build binaries: `cd dead-man-hand && make build`
4. Run dmh: `DMH_CONFIG_FILE=config.yaml ./dmh`

# Execute plugins

`DMH` is easily extensible and support below plugins:
* `dummy` - log action message
* `json_post` - send `HTTP` `POST` request
* `mail` - send mail over `SMTP`
* `bulksms` - send `SMS` with [bulksms.com](https://bulksms.com)

# Documentation
Documentation is available in [wiki](https://github.com/bkupidura/dead-man-hand/wiki)
