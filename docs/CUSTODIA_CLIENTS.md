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
| **Go** | Esistente | Transport SDK pubblico solido; crypto client pianificato | `pkg/client` nel monorepo, con payload e operational methods pubblici senza tipi `internal/*` nelle nuove API. |
| **Python** | Esistente | Transport client presente; crypto client pianificato | `clients/python` nel monorepo. |
| **Node.js / TypeScript** | Non presente | Pianificato | Da aggiungere dopo spec crypto e test vectors. |
| **Rust** | Non presente | Pianificato | Da aggiungere dopo Go/Python. |
| **Java** | Non presente | Pianificato | Da aggiungere dopo stabilizzazione schema crypto. |
| **C++** | Non presente | Pianificato | Da aggiungere per ultimo per complessità ABI/OpenSSL/packaging. |

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

Senza test vectors comuni, gli SDK non devono essere dichiarati ufficiali. La baseline attuale include fixture deterministiche per metadata/AAD, AES-256-GCM ciphertext e HPKE-v1 recipient envelopes. Questi vector sbloccano l'implementazione dei crypto client, ma Go/Python restano transport client finché i layer high-level E2E non sono implementati e documentati.

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

Gli esempi Node.js, Rust, Java e C++ devono essere aggiunti solo quando i rispettivi client sono presenti o quando sono chiaramente marcati come esempi raw HTTP non ufficiali.

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
| Node.js / TypeScript | `clients/node` | Pianificato. |
| Rust | `clients/rust` | Pianificato. |
| Java | `clients/java` | Pianificato. |
| C++ | `clients/cpp` | Pianificato. |

Nomi come `github.com/custodia/go-client`, `@custodia/client`, `custodia-client` o `com.custodia:client` sono placeholder finché non vengono pubblicati davvero.

### 8.1 Stabilizzazione SDK Go pubblico

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
2. **Fase 5B**: stabilizzare `pkg/client` come SDK Go pubblico senza tipi `internal/*`, chiudere i metodi transport pubblici e poi aggiungere Go high-level crypto client.
3. **Fase 5C**: Python high-level crypto client sopra `clients/python`.
4. **Fase 5D**: Node.js/TypeScript client.
5. **Fase 5E**: Rust client.
6. **Fase 5F**: Java client.
7. **Fase 5G**: C++ client.

Non implementare sei SDK in parallelo prima di avere crypto spec e test vectors comuni.

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
