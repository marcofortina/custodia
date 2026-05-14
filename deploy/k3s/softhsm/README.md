# Kubernetes SoftHSM lab example

This example is **lab-only**. It exists to exercise the Kubernetes Full PKCS#11 signer path when a real HSM is not available. SoftHSM stores key material on cluster storage and is not production HSM evidence unless your organization independently governs that environment as production-grade.

Use this example only for development, CI rehearsal or disposable lab clusters. For production, replace SoftHSM with a real HSM/TPM/vendor PKCS#11 module, managed PIN delivery, node scheduling controls, attestation evidence and audited operational ownership.

## What this example provides

- A lab image overlay that extends the normal Custodia image with SoftHSM, OpenSC, Python and the `custodia-pkcs11-sign` bridge.
- A PVC used by the signer pod and init Job to share the SoftHSM token store.
- A Secret example for the lab token PIN.
- A one-shot init Job that initializes the SoftHSM token and generates the signer key.
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
kubectl apply -f deploy/k3s/softhsm/custodia-softhsm-init-job.yaml
kubectl -n custodia wait --for=condition=complete job/custodia-softhsm-init --timeout=120s
```

The init Job creates the token store on the PVC and generates the lab signer key.

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

Then exercise certificate signing through the configured PKCS#11 command by creating and claiming a client enrollment token from outside the pod:

```bash
sudo -u custodia custodia-admin client enrollment create --ttl 15m

custodia-client mtls enroll \
  --client-id client_alice \
  --server-url https://SERVER_IP_OR_DNS:8443 \
  --enrollment-token TOKEN
```

A successful enrollment proves that the signer reached `CUSTODIA_SIGNER_PKCS11_SIGN_COMMAND`, the command reached SoftHSM, and the resulting certificate was returned to the client.

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
