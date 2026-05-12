# Kubernetes bootstrap material

This runbook generates the Kubernetes Secrets required by [`KUBERNETES_INSTALL.md`](KUBERNETES_INSTALL.md) without entering application pods. Run it from an operator workstation or build host that can run `custodia-admin` and `kubectl` against the target cluster.

The commands below are safe for a Lite/lab bootstrap and for release-candidate rehearsals. For Full production, replace local CA private-key material with your enterprise PKI/HSM procedure and keep private CA material out of ordinary Kubernetes Secrets whenever the platform supports that.

## 1. Build or install the admin CLI

From a Git checkout, this path requires a local Go toolchain:

```bash
git clone https://github.com/marcofortina/custodia.git
cd custodia
go version
make build-server
```

The local binary is:

```text
./custodia-admin
```

If you installed packages instead, use:

```text
custodia-admin
```

The examples below use `CUSTODIA_ADMIN=./custodia-admin`; change it if you installed the package.

```bash
CUSTODIA_ADMIN=./custodia-admin
```

## 2. Generate Lite/lab bootstrap files

Choose the externally reachable server name. It must match the DNS name or IP address clients and browsers will use and must later match Helm `config.serverURL`.

The same TLS Secret is mounted by the API/Web pod and the signer pod. The server talks to the signer through the Kubernetes Service name, so the generated server certificate must include both the external API/Web name and the internal signer Service DNS names. For the default release `custodia` and chart name `custodia`, the signer Service is `custodia-custodia-signer`. If you use `fullnameOverride`, `nameOverride` or a different release name, compute the signer Service names from the rendered chart first.

```bash
CUSTODIA_K8S_NAMESPACE=custodia
CUSTODIA_HELM_RELEASE=custodia
CUSTODIA_HELM_CHART_NAME=custodia
CUSTODIA_SERVER_NAME=custodia.example.internal
CUSTODIA_SIGNER_SERVICE="${CUSTODIA_HELM_RELEASE}-${CUSTODIA_HELM_CHART_NAME}-signer"
CUSTODIA_BOOTSTRAP_DIR="$(mktemp -d)"
chmod 700 "$CUSTODIA_BOOTSTRAP_DIR"
```

```bash
"$CUSTODIA_ADMIN" ca bootstrap-local \
  --out-dir "$CUSTODIA_BOOTSTRAP_DIR" \
  --admin-client-id admin \
  --server-name "$CUSTODIA_SERVER_NAME" \
  --server-san "$CUSTODIA_SIGNER_SERVICE" \
  --server-san "${CUSTODIA_SIGNER_SERVICE}.${CUSTODIA_K8S_NAMESPACE}" \
  --server-san "${CUSTODIA_SIGNER_SERVICE}.${CUSTODIA_K8S_NAMESPACE}.svc" \
  --generate-ca-passphrase
```

Expected files:

```text
admin.crt
admin.key
ca.crt
ca.key
ca.pass
client-ca.crt
client.crl.pem
server.crt
server.key
custodia-server.yaml
custodia-signer.yaml
```

The YAML files are useful for inspection, but Kubernetes installs use Helm values and Secrets instead of copying those files into pods. Keep the `server.crt` SAN list aligned with the rendered signer Service name; otherwise enrollment signing fails later when the API server verifies the signer TLS certificate.

Before deleting the bootstrap directory, you still need the admin certificate and key to create the browser client certificate package in step 6.

## 3. Generate Web MFA material

Generate a TOTP secret for the first admin account:

```bash
"$CUSTODIA_ADMIN" web totp generate --account admin --format json \
  > "$CUSTODIA_BOOTSTRAP_DIR/web-totp.json"
cat "$CUSTODIA_BOOTSTRAP_DIR/web-totp.json"
```

Copy the printed `provisioning_uri` into the operator authenticator/password manager. Then set the TOTP secret as a shell variable by pasting the printed `totp_secret` value:

```bash
CUSTODIA_WEB_TOTP_SECRET='PASTE_totp_secret_FROM_web-totp.json'
CUSTODIA_WEB_SESSION_SECRET="$(openssl rand -base64 48)"
```

Do not store these values in Helm values files or Git.

## 4. Create namespace and Secrets

```bash
kubectl create namespace custodia --dry-run=client -o yaml | kubectl apply -f -
```

API/Web mTLS Secret:

```bash
kubectl -n custodia create secret generic custodia-mtls \
  --from-file=tls.crt="$CUSTODIA_BOOTSTRAP_DIR/server.crt" \
  --from-file=tls.key="$CUSTODIA_BOOTSTRAP_DIR/server.key" \
  --from-file=ca.crt="$CUSTODIA_BOOTSTRAP_DIR/client-ca.crt" \
  --from-file=client.crl.pem="$CUSTODIA_BOOTSTRAP_DIR/client.crl.pem"
```

Signer CA material Secret for Lite/lab:

```bash
kubectl -n custodia create secret generic custodia-signer-ca \
  --from-file=ca.crt="$CUSTODIA_BOOTSTRAP_DIR/ca.crt" \
  --from-file=ca.key="$CUSTODIA_BOOTSTRAP_DIR/ca.key" \
  --from-file=ca.pass="$CUSTODIA_BOOTSTRAP_DIR/ca.pass" \
  --from-file=client.crl.pem="$CUSTODIA_BOOTSTRAP_DIR/client.crl.pem"
```

Server-to-signer client mTLS Secret:

```bash
kubectl -n custodia create secret generic custodia-signer-client \
  --from-file=tls.crt="$CUSTODIA_BOOTSTRAP_DIR/admin.crt" \
  --from-file=tls.key="$CUSTODIA_BOOTSTRAP_DIR/admin.key" \
  --from-file=ca.crt="$CUSTODIA_BOOTSTRAP_DIR/ca.crt"
```

Web MFA Secret:

```bash
kubectl -n custodia create secret generic custodia-web-mfa \
  --from-literal=totp-secret="$CUSTODIA_WEB_TOTP_SECRET" \
  --from-literal=session-secret="$CUSTODIA_WEB_SESSION_SECRET"
```

## 5. Wire the Helm values

The committed Lite and Full examples already expect these Secret names:

```yaml
mtls:
  clientCRLKey: client.crl.pem
web:
  mfaSecretName: custodia-web-mfa
  totpSecretKey: totp-secret
  sessionSecretKey: session-secret
signer:
  secretName: custodia-signer-ca
  clientSecretName: custodia-signer-client
```

Set `config.serverURL` to the same name used for `CUSTODIA_SERVER_NAME`:

```yaml
config:
  serverURL: "https://custodia.example.internal:8443"
```

## 6. Prepare the admin browser certificate

The first Web Console login requires the admin mTLS certificate. Create the browser-importable package before deleting `CUSTODIA_BOOTSTRAP_DIR`:

```bash
openssl pkcs12 -export \
  -in "$CUSTODIA_BOOTSTRAP_DIR/admin.crt" \
  -inkey "$CUSTODIA_BOOTSTRAP_DIR/admin.key" \
  -certfile "$CUSTODIA_BOOTSTRAP_DIR/ca.crt" \
  -out "$CUSTODIA_BOOTSTRAP_DIR/custodia-admin.p12" \
  -name "Custodia Admin"
```

Import `custodia-admin.p12` into the operator browser certificate store, then keep or archive it according to your admin certificate custody policy.

## 7. Full profile PKCS#11/HSM delivery

For Full Kubernetes, `signer.keyProvider: pkcs11` is not enough. The signer container must actually contain or mount the command configured in `signer.pkcs11SignCommand`.

Choose exactly one delivery model:

```yaml
signer:
  keyProvider: pkcs11
  pkcs11SignCommand: /usr/local/bin/custodia-pkcs11-sign
  pkcs11SignCommandDelivery: custom-image
```

Use `custom-image` only after extending the base Custodia image so it actually contains the HSM bridge and all required PKCS#11 libraries. The stock `deploy/Dockerfile` image does not install `/usr/local/bin/custodia-pkcs11-sign`.

Or:

```yaml
signer:
  keyProvider: pkcs11
  pkcs11SignCommand: /opt/custodia/pkcs11/custodia-pkcs11-sign
  pkcs11SignCommandDelivery: volume
  extraVolumeMounts:
    - name: pkcs11-helper
      mountPath: /opt/custodia/pkcs11
      readOnly: true
  extraVolumes:
    - name: pkcs11-helper
      configMap:
        name: custodia-pkcs11-helper
        defaultMode: 0555
```

The Helm chart fails closed for Full PKCS#11 when the command path or delivery model is missing. The volume example is only a wiring pattern; production HSM libraries, tokens, sockets, credentials and node scheduling must be covered by your platform security review.

## 8. Clean up local bootstrap material

After the Kubernetes Secrets exist, Web MFA is enrolled and the admin browser certificate package has been imported or archived, remove the temporary directory from the operator workstation unless your release evidence policy explicitly archives it in a protected vault:

```bash
rm -rf "$CUSTODIA_BOOTSTRAP_DIR"
unset CUSTODIA_WEB_TOTP_SECRET CUSTODIA_WEB_SESSION_SECRET
```
