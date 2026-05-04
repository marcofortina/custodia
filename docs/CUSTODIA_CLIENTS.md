# Custodia – Specifica Fase 5 delle librerie client ufficiali

## 1. Panoramica

Le librerie client di **Custodia** permettono alle applicazioni di interagire con il vault mantenendo il modello di sicurezza end-to-end: i secret sono cifrati e decifrati esclusivamente lato client; il server vede solo metadata, ciphertext ed envelope opachi.

Questa specifica non deve dichiarare come già ufficiali librerie che non esistono ancora nel repository. La Fase 5 introduce una roadmap implementabile, basata su due livelli distinti:

1. **Transport client**: client REST/mTLS che invia e riceve payload già opachi.
2. **Crypto client**: livello alto, da implementare, che cifra plaintext, crea envelope, decifra ciphertext e condivide secret usando chiavi risolte localmente.

Principi comuni:

- **mTLS obbligatorio** per tutte le chiamate API `/v1/*`.
- **Nessun plaintext inviato al server**.
- **Nessuna chiave privata o DEK inviata al server**.
- **Nessuna dipendenza da chiavi pubbliche gestite dal server**: il client risolve le chiavi dei destinatari localmente o tramite resolver applicativo.
- **Envelope e ciphertext versionati** per garantire interoperabilità tra linguaggi.
- **API REST coerente** con `Vault-REST.md` e con la documentazione principale.

---

## 2. Stato reale dei client

| Linguaggio | Stato repository | Stato Fase 5 | Note |
|------------|------------------|--------------|------|
| **Go** | Esistente | Transport SDK pubblico + primo crypto client high-level E2E | `pkg/client` nel monorepo, con payload/operational methods pubblici e crypto helpers senza esporre tipi `internal/*` nelle API. |
| **Python** | Esistente | Transport client + primo crypto client high-level E2E | `clients/python` nel monorepo, con typed transport helpers e crypto wrapper basato sugli stessi vector. |
| **Node.js / TypeScript** | Esistente | Transport client presente; crypto client presente | `clients/node` nel monorepo, con JavaScript runtime dependency-free, crypto high-level HPKE-v1/AES-GCM e dichiarazioni TypeScript. |
| **Rust** | Esistente | Transport client presente; crypto client presente | `clients/rust` nel monorepo, con transport REST/mTLS e crypto high-level HPKE-v1/AES-GCM basato sugli stessi vector. |
| **Java** | Esistente | Transport client presente; crypto client presente | `clients/java` nel monorepo, basato su `java.net.http`, SSLContext/keystore Java e crypto high-level. |
| **C++** | Esistente | Transport client presente; crypto client presente | `clients/cpp` nel monorepo, basato su libcurl per HTTPS/mTLS e OpenSSL per crypto high-level. |

## 2.1 Matrice capacità SDK

| Client | Transport REST/mTLS | Crypto high-level | Note |
| --- | --- | --- | --- |
| Go | Sì | Sì | Include metodi operational pubblici. |
| Python | Sì | Sì | Typed transport + crypto wrapper. |
| Node.js / TypeScript | Sì | Sì | Runtime JS + dichiarazioni TypeScript. |
| Java | Sì | Sì | Transport `java.net.http` + crypto locale. |
| C++ | Sì | Sì | libcurl + OpenSSL. |
| Rust | Sì | Sì | reqwest/rustls + crypto locale. |
| Bash | Sì | No native / external provider bridge | Helper shell: crypto solo tramite provider esterno verificabile, non implementata in Bash. |

Una libreria diventa “ufficiale” solo quando ha:

- codice nel repository o repository dedicato approvato;
- test mTLS/REST;
- test crypto con test vectors comuni;
- documentazione di installazione e uso;
- CI o comando di verifica riproducibile;
- policy chiara su retry, timeout e logging sicuro.

---

## 3. Architettura dei client

### 3.1 Transport client

Il transport client parla con il server Custodia senza implementare crypto locale automatica.

Operazioni principali:

| Operazione | Descrizione |
|------------|-------------|
| `CreateSecret(payload)` | Invia `name`, `ciphertext`, `envelopes`, permessi e metadata già opachi. |
| `GetSecret(secretID)` | Recupera ciphertext ed envelope opaco autorizzato. |
| `CreateSecretVersion(secretID, payload)` | Crea una nuova versione con payload già cifrato. |
| `ShareSecret(secretID, envelopePayload)` | Invia un nuovo envelope prodotto fuori dal server. |
| `RevokeAccess(secretID, clientID)` | Revoca accesso lato server. |
| `ListSecrets()` / `ListSecretVersions()` | Legge metadata autorizzati. |

Questo livello non deve mai provare a interpretare ciphertext, envelope o chiavi.

### 3.2 Crypto client

Il crypto client è il livello alto della Fase 5. Usa il transport client, ma aggiunge cifratura/decrittazione locale.

Operazioni previste:

| Operazione | Descrizione |
|------------|-------------|
| `CreateEncryptedSecret(name, plaintext, recipients, permissions)` | Genera DEK, cifra plaintext, crea envelope per ogni destinatario e invia payload opaco. |
| `ReadDecryptedSecret(secretID)` | Recupera ciphertext/envelope, decifra envelope localmente, poi decifra ciphertext. |
| `ShareEncryptedSecret(secretID, targetClientID)` | Recupera/usa la DEK locale autorizzata e crea un envelope per il nuovo destinatario. |
| `CreateEncryptedSecretVersion(secretID, plaintext, recipients)` | Crea una nuova versione cifrata localmente. |

Il crypto client richiede componenti espliciti:

```text
PublicKeyResolver.resolve(client_id) -> recipient public key
PrivateKeyProvider.current() -> local private key material or signer/decrypter handle
RandomSource -> CSPRNG language-native
Clock -> testability for metadata timestamps where needed
```

Il server Custodia non diventa mai una public-key directory.

---

## 4. Specifica crypto comune

Prima di implementare i crypto client multi-linguaggio serve una specifica unica, versionata e testabile.

Documento da produrre nella Fase 5A:

```text
docs/CLIENT_CRYPTO_SPEC.md
```

Requisiti minimi:

- formato `ciphertext`;
- formato `envelope`;
- `crypto_metadata` versionato;
- algoritmo DEK;
- algoritmo AEAD;
- schema envelope;
- AAD obbligatorio;
- identificatore schema, per esempio `hpke-v1`;
- error model comune;
- test vectors JSON condivisi.

Scelta consigliata per nuovi client:

```text
envelope_scheme: hpke-v1
content_cipher: aes-256-gcm oppure xchacha20-poly1305
```

Non scegliere schemi diversi per linguaggio. Se serve compatibilità legacy, introdurre schemi versionati, per esempio:

```text
envelope_scheme: hpke-v1
envelope_scheme: rsa-oaep-aes-gcm-legacy
```

ma la scelta deve essere per **schema/versione**, non per Go/Python/Java/Rust.

---

## 5. Test vectors obbligatori

Tutti i crypto client devono passare gli stessi test vectors.

Percorso proposto:

```text
testdata/client-crypto/v1/
```

Test vectors minimi:

| File | Scopo |
|------|-------|
| `create_secret_single_recipient.json` | Creazione secret per un destinatario. |
| `create_secret_multi_recipient.json` | Creazione secret per più destinatari. |
| `read_secret_authorized_recipient.json` | Decifratura destinatario autorizzato. |
| `share_secret_add_recipient.json` | Creazione nuovo envelope per condivisione. |
| `tamper_ciphertext_fails.json` | Alterazione ciphertext deve fallire. |
| `wrong_recipient_fails.json` | Envelope di altro client non deve decifrare. |
| `aad_mismatch_fails.json` | AAD non coerente deve fallire. |
| `unsupported_crypto_version_fails.json` | Versione non supportata deve fallire chiaramente. |

Senza test vectors comuni, gli SDK non devono essere dichiarati ufficiali. La baseline attuale include fixture deterministiche per metadata/AAD, AES-256-GCM ciphertext e HPKE-v1 recipient envelopes. Questi vector alimentano i crypto client high-level E2E per Go, Python, Node.js/TypeScript, Java, C++, Rust e il contratto dei provider esterni Bash.

---

## 6. Esempi di utilizzo

Gli esempi sotto sono esempi **raw transport REST**, non esempi del futuro crypto client high-level.

### 6.1 Go – raw transport example

```go
package main

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io"
    "net/http"
    "os"
    "strings"
)

func main() {
    caCert, err := os.ReadFile("ca.crt")
    if err != nil { panic(err) }
    caPool := x509.NewCertPool()
    if !caPool.AppendCertsFromPEM(caCert) { panic("invalid CA") }

    cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
    if err != nil { panic(err) }

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caPool,
        MinVersion:   tls.VersionTLS12,
    }
    client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

    payload := `{"name":"test","ciphertext":"base64cipher","envelopes":[{"client_id":"self","envelope":"base64env"}]}`
    resp, err := client.Post("https://vault:8443/v1/secrets", "application/json", strings.NewReader(payload))
    if err != nil { panic(err) }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
}
```

### 6.2 Python – raw transport example

```python
import base64
import requests

session = requests.Session()
session.cert = ("client.crt", "client.key")
session.verify = "ca.crt"

payload = {
    "name": "test",
    "ciphertext": base64.b64encode(b"already-encrypted-data").decode(),
    "envelopes": [
        {"client_id": "self", "envelope": base64.b64encode(b"already-produced-envelope").decode()}
    ],
}

resp = session.post("https://vault:8443/v1/secrets", json=payload, timeout=10)
resp.raise_for_status()
print(resp.json())
```

### 6.3 Node.js / TypeScript – raw transport example

```js
import { CustodiaClient, PermissionAll } from "@custodia/client";

const client = new CustodiaClient({
    serverUrl: "https://vault:8443",
    certFile: "client.crt",
    keyFile: "client.key",
    caFile: "ca.crt",
});

const created = await client.createSecretPayload({
    name: "test",
    ciphertext: "base64cipher",
    envelopes: [
        { client_id: "self", envelope: "base64env" },
    ],
    permissions: PermissionAll,
});

console.log(created);
```

Gli esempi completi per Rust, Java e C++ sono mantenuti nei rispettivi documenti SDK per evitare duplicazione e drift in questa specifica.

---

## 7. Funzionalità comuni

### 7.1 Transport layer comune

Tutti i transport client ufficiali devono supportare:

- configurazione mTLS;
- root CA custom;
- timeout configurabili;
- user-agent/versione client;
- errori tipizzati per status HTTP;
- nessun logging di ciphertext, envelope, plaintext, DEK, private key o passphrase;
- retry solo per operazioni idempotenti o quando esiste una idempotency key esplicita.

Regola retry:

```text
GET/list/status: retry ammesso con backoff.
POST/PUT/PATCH/DELETE: retry vietato di default salvo idempotency key o semantica documentata.
```

### 7.2 Crypto layer comune

Tutti i crypto client ufficiali devono supportare:

- `PublicKeyResolver` applicativo;
- `PrivateKeyProvider` locale;
- CSPRNG language-native;
- test vectors comuni;
- crypto metadata versionato;
- errori chiari su recipient errato, AAD mismatch, ciphertext alterato, versione crypto non supportata.

---

## 8. Repository e pacchetti

Per la Fase 5 iniziale usare il monorepo:

| Linguaggio | Posizione iniziale | Pacchetto pubblico |
|------------|--------------------|--------------------|
| Go | `pkg/client` | Da decidere. |
| Python | `clients/python` | Da decidere. |
| Node.js / TypeScript | `clients/node` | Monorepo private scaffold; nome pubblico da decidere. |
| Rust | `clients/rust` | Monorepo transport + crypto scaffold; nome pubblico da decidere. |
| Java | `clients/java` | Monorepo transport + crypto scaffold; nome pubblico da decidere. |
| C++ | `clients/cpp` | Monorepo transport + crypto scaffold; nome pubblico da decidere. |
| Bash | `clients/bash` | Helper shell con transport REST/mTLS e bridge opzionale a provider crypto esterno; non ha package pubblico. |

Nomi come `github.com/custodia/go-client`, `@custodia/client`, `custodia-client` o `com.custodia:client` sono placeholder finché non vengono pubblicati davvero.

### 8.1 Stabilizzazione SDK Node.js / TypeScript transport

`clients/node` esiste nel repository come transport client per payload opachi. Il transport resta separato dal wrapper crypto high-level.

Surface attuale:

- runtime JavaScript ESM senza dipendenze npm runtime;
- dichiarazioni TypeScript in `src/index.d.ts`;
- configurazione mTLS tramite `certFile`, `keyFile`, `caFile`;
- timeout configurabile;
- user-agent configurabile;
- errore tipizzato `CustodiaHttpError`;
- metodi transport per secret, access grants, client metadata, operational status, revocation e audit export.

Criterio di confine:

```text
clients/node transport -> invia solo payload già opachi e non prova a cifrare, decifrare, loggare o interpretare ciphertext/envelope/crypto_metadata
```

Il package resta `private` finché non vengono definiti nome pubblico, release process e support policy.

### 8.2 Stabilizzazione SDK Go pubblico

`pkg/client` esiste nel repository ed è utilizzabile come transport client interno/al modulo, ma prima di dichiararlo SDK Go pubblico stabile deve smettere di esporre tipi da package `internal/*` nelle API pubbliche.

Problema da correggere in Fase 5B:

```text
pkg/client public API -> non deve richiedere import di custodia/internal/model o custodia/internal/mtls
```

Direzione richiesta:

- introdurre tipi pubblici stabili in `pkg/client`, per esempio `CreateSecretRequest`, `RecipientEnvelope`, `SecretReadResponse`, `ClientInfo`, `AccessGrantRequest`;
- mantenere la conversione verso `internal/model` solo dentro il repository;
- evitare che un progetto Go esterno debba importare package `internal/*`;
- documentare un import path pubblico o monorepo-supported dopo la stabilizzazione;
- aggiungere test che compilano un consumer Go esterno minimale contro `pkg/client`.

Criterio di chiusura:

```text
un progetto Go esterno deve poter importare pkg/client e parlare con custodia-server senza dipendere da internal/*
```

---


### 8.3 Stabilizzazione SDK Node.js / TypeScript crypto

`clients/node` espone anche un wrapper high-level crypto client che resta coerente con Go/Python/Java/C++/Rust:

- AES-256-GCM per content encryption;
- HPKE-v1 su X25519/HKDF-SHA256/AES-256-GCM per recipient envelope;
- `CanonicalAADInputs` e `CryptoMetadata` compatibili con i vector comuni;
- `PublicKeyResolver` e `PrivateKeyProvider` applicativi, senza directory di chiavi sul server;
- nessun plaintext, DEK o chiave privata inviati al vault.

Il package resta `private` finché nome pubblico e release process non sono decisi, ma la superficie API è verificata dai test Node e dai vector comuni.

### 8.4 Stabilizzazione SDK Java transport e crypto

`clients/java` esiste nel repository come client Java iniziale per payload opachi e crypto client high-level. Usa solo librerie standard Java e accetta un `SSLContext` applicativo oppure keystore/truststore Java per mTLS.

Surface attuale:

- `CustodiaClientConfig` per server URL, timeout, user-agent e TLS material;
- `CustodiaClient` con metodi transport per secrets, grants, clients, status, diagnostics, revocation e audit export;
- `CustodiaHttpError` tipizzato per status HTTP non 2xx;
- `CustodiaAuditExport` con body, digest SHA-256 e numero eventi;
- `CustodiaCrypto` con canonical AAD, AES-256-GCM, HPKE-v1/X25519 e resolver/provider applicativi;
- `CryptoCustodiaClient` per create/read/share/version con cifratura locale.

Criterio di confine:

```text
clients/java crypto -> cifra/decifra localmente, risolve le chiavi pubbliche solo tramite resolver applicativo e invia al server solo ciphertext, crypto_metadata ed envelope opachi
```

Il crypto client Java usa gli stessi vector comuni di Go/Python/Node/C++/Rust.

### 8.5 Stabilizzazione SDK C++ transport e crypto

`clients/cpp` esiste nel repository come client C++ iniziale per payload opachi e crypto client high-level. Usa libcurl per HTTPS/mTLS, OpenSSL per AES-GCM/X25519/HKDF e una piccola API C++20 senza introdurre un framework di build dedicato.

Surface attuale:

- `custodia::Config` per server URL, timeout, user-agent e file TLS;
- `custodia::Client` con metodi transport per secrets, grants, clients, status, diagnostics, revocation e audit export;
- `custodia::HttpError` per status HTTP non 2xx;
- `custodia::AuditExportArtifact` con body, digest SHA-256 e numero eventi;
- primitive crypto v1 per canonical AAD, AES-256-GCM e HPKE-v1/X25519;
- `custodia::CryptoClient` per create/read/share/version con cifratura locale.

Criterio di confine:

```text
clients/cpp crypto -> cifra/decifra localmente, risolve le chiavi pubbliche solo tramite resolver applicativo e invia al server solo ciphertext, crypto_metadata ed envelope opachi
```

Il crypto client C++ usa gli stessi vector comuni di Go/Python/Node/Java/Rust; la dipendenza crypto esplicita è OpenSSL.

### 8.6 Stabilizzazione SDK Rust transport e crypto

`clients/rust` esiste nel repository come client Rust per payload opachi e crypto client high-level. Usa `reqwest` blocking con TLS rustls per HTTPS/mTLS, `serde_json::Value` per il transport e primitive crypto Rust per canonical AAD, AES-256-GCM e HPKE-v1/X25519.

Surface attuale:

- `CustodiaClientConfig` per server URL, timeout, user-agent e file TLS;
- `CustodiaClient` con metodi transport per secrets, grants, clients, status, diagnostics, revocation e audit export;
- `CustodiaError::Http` tipizzato per status HTTP non 2xx;
- `AuditExportArtifact` con body, digest SHA-256 e numero eventi;
- `HttpTransport` trait per test e integrazioni custom;
- `CryptoCustodiaClient` per create/read/share/version con cifratura locale;
- `CryptoOptions`, `PublicKeyResolver`, `PrivateKeyProvider` e `RandomSource`;
- primitive v1 per canonical AAD, AES-256-GCM e HPKE-v1/X25519.

Criterio di confine:

```text
clients/rust crypto -> cifra/decifra localmente, risolve le chiavi pubbliche solo tramite resolver applicativo e invia al server solo ciphertext, crypto_metadata ed envelope opachi
```

Il package resta `publish = false` finché nome pubblico e release process non sono decisi.

### 8.7 Bash transport helper fuori SDK crypto

`clients/bash` esiste nel repository come helper shell per CI, smoke test e script operativi basati su `curl`. Il codice Bash resta transport-only, ma può delegare flussi cifrati a un provider crypto esterno configurato con `CUSTODIA_CRYPTO_PROVIDER`.

Criterio di confine:

```text
clients/bash -> helper REST/mTLS; crypto opzionale solo tramite provider esterno stdin/stdout, nessuna crypto applicativa implementata in Bash
```

Questo evita di promuovere Bash a superficie crypto nativa fragile per shell history, process list, escaping JSON/base64 e logging accidentale. Il provider esterno deve implementare canonical AAD, AES-256-GCM, HPKE-v1 e passare i vector comuni; Bash orchestri solo file JSON e payload opachi.

## 9. Note sulla sicurezza

- **Mai condividere la chiave privata**: ogni client mantiene la propria chiave privata o handle di decrittazione in locale.
- **Mai inviare plaintext al server**.
- **Mai inviare DEK al server**.
- **Mai usare il vault come public-key directory**.
- **Le chiavi pubbliche dei destinatari** devono essere ottenute tramite canale sicuro: file locale, KMS, directory aziendale, provisioning out-of-band o resolver applicativo.
- **Il logging deve essere safe-by-default**: niente plaintext, ciphertext, envelope, DEK, private key, passphrase, bearer/session material.
- **La rotazione certificati mTLS** nei client deve essere locale (`reload_tls_identity` o equivalente). Il lifecycle server-side dei certificati resta responsabilità di admin/signer/API dedicate.

---

## 10. Roadmap Fase 5

Ordine consigliato:

1. **Fase 5A**: riallineamento specifica client, `CLIENT_CRYPTO_SPEC.md`, test vectors.
2. **Fase 5B**: stabilizzare `pkg/client` come SDK Go pubblico senza tipi `internal/*`, chiudere i metodi transport/operational pubblici e aggiungere il primo Go high-level crypto client.
3. **Fase 5C**: Python high-level crypto client sopra `clients/python`.
4. **Fase 5D**: Node.js/TypeScript transport client e high-level crypto wrapper sopra gli stessi vector comuni.
5. **Fase 5E**: Rust transport client e high-level crypto wrapper presenti.
6. **Fase 5F**: Java transport client e high-level crypto wrapper presenti.
7. **Fase 5G**: C++ transport client e high-level crypto wrapper presenti.
8. **Post-roadmap**: Bash transport helper per CI/smoke/ops, esplicitamente fuori dal set crypto SDK.

Non implementare sei SDK in parallelo prima di avere crypto spec e test vectors comuni.

Stato repository: la Fase 5 è chiusa a livello di monorepo con SDK transport Go/Python/Node/Java/C++/Rust, crypto high-level Go/Python/Node/Java/C++/Rust e vector comuni. Pubblicazione pacchetti e policy semver restano lavori futuri fuori da questa chiusura.

---

## 11. Criteri di accettazione

Una libreria client può essere marcata ufficiale solo se:

- compila e passa test nel repository;
- usa mTLS obbligatorio;
- non richiede una public-key directory server-side;
- passa tutti i test vectors crypto comuni;
- documenta installazione, configurazione TLS e limiti di sicurezza;
- non logga materiale sensibile;
- espone API coerenti con gli altri linguaggi;
- mantiene compatibilità con `Vault-REST.md`.

## SDK release policy

SDK publication and versioning rules are defined in [`SDK_RELEASE_POLICY.md`](SDK_RELEASE_POLICY.md).

The Linux `custodia-clients` package is a source snapshot and Bash helper distribution. Native registry publication remains separate and must follow each ecosystem's release process.
