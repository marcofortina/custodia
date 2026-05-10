# Custodia Bash SDK helper

`clients/bash/custodia.bash` is a sourceable Bash helper library around the
`custodia-client` CLI.

It is intended for shell scripts that already use Custodia client profiles and
want small Bash functions instead of repeating long `custodia-client` command
lines.

Native Bash code does **not** implement application cryptography. Encryption,
decryption, HPKE envelopes, key loading and mTLS transport remain handled by the
Go `custodia-client` binary.

## Usage

```bash
source /usr/share/custodia/sdk/clients/bash/custodia.bash

custodia_use_client_id client_alice
custodia_config_check
custodia_doctor --online

printf 'secret value' > /tmp/secret.txt
custodia_secret_put_file smoke-demo /tmp/secret.txt
custodia_secret_get_file smoke-demo /tmp/readback.txt
```

Functions:

- `custodia_use_client_id CLIENT_ID`
- `custodia_use_config CONFIG`
- `custodia_config_check`
- `custodia_doctor [--online]`
- `custodia_secret_put_file KEY VALUE_FILE [NAMESPACE]`
- `custodia_secret_get_file KEY OUTPUT_FILE [NAMESPACE]`
- `custodia_secret_update_file KEY VALUE_FILE [NAMESPACE]`
- `custodia_secret_share KEY TARGET_CLIENT_ID RECIPIENT_SPEC [PERMISSIONS] [NAMESPACE]`
- `custodia_secret_revoke KEY TARGET_CLIENT_ID [NAMESPACE]`
- `custodia_secret_delete KEY [NAMESPACE]`
- `custodia_secret_delete_cascade KEY [NAMESPACE]`

## Security boundary

- Do not run shell scripts with `set -x` around secret operations.
- Do not put plaintext, DEKs, private keys or passphrases in shell history.
- Protect client profiles and local crypto keys under `$XDG_CONFIG_HOME/custodia` or `$HOME/.config/custodia`.
- Use trusted out-of-band exchange for recipient public-key files.
