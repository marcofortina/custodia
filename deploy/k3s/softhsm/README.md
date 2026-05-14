# Kubernetes SoftHSM lab example

This example is **lab-only**. It exists to exercise the Kubernetes Full PKCS#11 signer path when a real HSM is not available. SoftHSM stores key material on cluster storage and is not production HSM evidence unless your organization independently governs that environment as production-grade.

Use this example only for development, CI rehearsal or disposable lab clusters. For production, replace SoftHSM with a real HSM/TPM/vendor PKCS#11 module, managed PIN delivery, node scheduling controls, attestation evidence and audited operational ownership.

## What this example provides

- A lab image overlay that extends the normal Custodia image with SoftHSM, OpenSC, OpenSSL, Python and the `custodia-pkcs11-sign` bridge.
- A PVC used by the signer pod and init Job to share the SoftHSM token store.
- A Secret example for the lab token PIN.
- A one-shot init Job that initializes the SoftHSM token and imports the existing signer CA private key from `custodia-signer-ca`.
- Helm values that run the Full profile with `signer.keyProvider=pkcs11` and explicit PKCS#11 command delivery.

## Build the base image

Build the normal universal Custodia image first:

```bash
export CUSTODIA_RELEASE=0.4.0-lab
export CUSTODIA_COMMIT="$(git rev-parse --short HEAD)"
export CUSTODIA_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export CUSTODIA_IMAGE=registry.example.internal/custodia/custodia:${CUSTODIA_RELEASE}

DOCKER_BUILDKIT=1 docker build \
  -f deploy/Dockerfile \
  --build-arg GO_BUILD_TAGS="sqlite postgres" \
  --build-arg CUSTODIA_VERSION="$CUSTODIA_RELEASE" \
  --build-arg CUSTODIA_COMMIT="$CUSTODIA_COMMIT" \
  --build-arg CUSTODIA_DATE="$CUSTODIA_DATE" \
  -t "$CUSTODIA_IMAGE" .
```

## Build the lab SoftHSM image

The lab image is intentionally separate from the production image:

```bash
export CUSTODIA_SOFTHSM_IMAGE=registry.example.internal/custodia/custodia-softhsm-lab:${CUSTODIA_RELEASE}

DOCKER_BUILDKIT=1 docker build \
  -f deploy/k3s/softhsm/Dockerfile \
  --build-arg CUSTODIA_IMAGE="$CUSTODIA_IMAGE" \
  -t "$CUSTODIA_SOFTHSM_IMAGE" .
```

Push both images to the registry used by your lab cluster.

## Create lab-only Kubernetes material

Review every placeholder before applying these files. Do not reuse the example PIN outside a disposable lab.

```bash
kubectl apply -f deploy/k3s/softhsm/custodia-softhsm-secret.example.yaml
kubectl apply -f deploy/k3s/softhsm/custodia-softhsm-conf.yaml
kubectl apply -f deploy/k3s/softhsm/custodia-softhsm-pvc.yaml
kubectl get secret -n custodia custodia-signer-ca
kubectl apply -f deploy/k3s/softhsm/custodia-softhsm-init-job.yaml
kubectl -n custodia wait --for=condition=complete job/custodia-softhsm-init --timeout=120s
```

The init Job creates the token store on the PVC and imports the existing signer CA private key from the `custodia-signer-ca` Secret into SoftHSM. This keeps `/etc/custodia/signer/ca.crt` and the PKCS#11 private key aligned. It does not generate an unrelated signer key.

If you previously initialized this lab with an older job that generated a random SoftHSM key, reset the lab token store before rerunning the init Job:

```bash
kubectl -n custodia scale deploy/custodia-custodia-signer --replicas=0
kubectl -n custodia delete job custodia-softhsm-init --ignore-not-found
kubectl -n custodia delete pvc custodia-softhsm-tokens
kubectl apply -f deploy/k3s/softhsm/custodia-softhsm-pvc.yaml
kubectl apply -f deploy/k3s/softhsm/custodia-softhsm-init-job.yaml
kubectl -n custodia wait --for=condition=complete job/custodia-softhsm-init --timeout=120s
```

## Render and install with Helm

Copy `custodia-values.example.yaml`, replace image registry, DNS, database, Valkey, mTLS, signer and Web MFA Secret placeholders, then render the chart:

```bash
helm template custodia deploy/helm/custodia \
  --values deploy/k3s/softhsm/custodia-values.example.yaml >/tmp/custodia-softhsm-render.yaml

make helm-check
```

Then install according to `docs/KUBERNETES_INSTALL.md`.

## Runtime smoke

After Helm install, verify the signer pod sees the configured command and token material through normal Kubernetes rollout/status checks:

```bash
kubectl -n custodia rollout status deploy/custodia-custodia-server
kubectl -n custodia rollout status deploy/custodia-custodia-signer
```

For a disposable lab without governed Ingress or LoadBalancer plumbing, expose the API through the lab-only NodePort manifest and set `server.serverURL` in the copied Helm values to the node endpoint. Do not use this manifest as production ingress or network-policy evidence.

```bash
kubectl apply -f deploy/k3s/softhsm/custodia-server-nodeport.yaml
kubectl -n custodia get svc custodia-custodia-server-lab-nodeport -o wide

# Example for a single-node lab. Use an address present in the server certificate SANs.
# server:
#   serverURL: "https://NODE_IP_OR_DNS:30443"
```

Then exercise certificate signing through the configured PKCS#11 command by creating and claiming a fresh client enrollment token. Use a new `client_id` for each smoke run so previous successful enrollments do not turn retries into expected `409 Conflict` responses.

```bash
SERVER_POD="$(kubectl -n custodia get pod -l app.kubernetes.io/component=server -o jsonpath='{.items[0].metadata.name}')"

kubectl -n custodia exec "$SERVER_POD" -- sh -c '
  custodia-admin \
    --cert /etc/custodia/signer-client/tls.crt \
    --key /etc/custodia/signer-client/tls.key \
    --ca /etc/custodia/signer-client/ca.crt \
    client enrollment create \
    --config /proc/self/fd/3 \
    --ttl 15m 3<<EOF
profile: full
server:
  url: "https://127.0.0.1:8443"
EOF
'

export ALICE_ID="client_alice_softhsm_$(date +%H%M%S)"
export CUSTODIA_SERVER_URL="https://NODE_IP_OR_DNS:30443"
export ALICE_ENROLLMENT_TOKEN="TOKEN"

custodia-client mtls enroll \
  --client-id "$ALICE_ID" \
  --server-url "$CUSTODIA_SERVER_URL" \
  --enrollment-token "$ALICE_ENROLLMENT_TOKEN" \
  --insecure

custodia-client key generate --client-id "$ALICE_ID"
custodia-client config write --client-id "$ALICE_ID"
custodia-client config check --client-id "$ALICE_ID"
custodia-client doctor --client-id "$ALICE_ID" --online
```

A successful enrollment and online doctor prove that the signer reached `CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND`, the command reached SoftHSM, the SoftHSM private key matches the configured signer CA certificate, and the resulting certificate was returned to a real client profile.

For read-only cluster checks, also run:

```bash
export CUSTODIA_K8S_NAMESPACE=custodia
export CUSTODIA_HELM_RELEASE=custodia
export CUSTODIA_K8S_PROFILE=full
export CUSTODIA_K8S_CONFIRM=YES
./scripts/kubernetes-runtime-smoke.sh cluster-check
```

## Replacing SoftHSM with a real HSM

For production, replace this lab setup with:

- a real HSM, TPM-backed signer or vendor PKCS#11 provider;
- a production image or mounted helper owned by the platform/security team;
- a module path and token/key labels from the HSM owner;
- PIN or authentication material delivered by a secrets manager;
- signer node placement, network and device controls;
- HSM attestation and operational evidence;
- WORM/SIEM audit shipment and revocation drill evidence.

Keep `signer.keyProvider=pkcs11` and point `signer.pkcs11SignCommand` to the production helper. Use `signer.pkcs11SignCommandDelivery=custom-image` when the helper is baked into the image, or `volume` when a reviewed volume mount delivers it at runtime.
