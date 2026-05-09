# Custodia Bash SDK helper

`clients/bash/custodia.bash` is a sourceable Bash helper around the `custodia-client` CLI. It is installed by the `custodia-sdk` package under:

```text
/usr/share/custodia/sdk/clients/bash/custodia.bash
```

It is intended for shell automation that already uses `custodia-client` profiles. It is not a standalone transport command and it does not implement cryptography itself.

## Usage

```bash
source /usr/share/custodia/sdk/clients/bash/custodia.bash
custodia_use_config "$HOME/.config/custodia/client_alice/client_alice.config.json"

custodia_config_check
custodia_doctor --online
custodia_secret_put_file smoke-demo ./secret.txt ./secret.create.json
custodia_secret_get_file "$SECRET_ID" ./readback.txt
custodia_secret_delete "$SECRET_ID"
```

## Security boundary

The helper delegates all network and cryptographic work to `custodia-client`. Plaintext, mTLS private keys and application private keys remain under the local user profile configured in the client JSON file.

Do not use shell tracing with commands that handle plaintext file paths or sensitive output files.

## Verification

```bash
make test-bash-client
```
