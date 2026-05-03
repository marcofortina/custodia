# Documento Tecnico Aggiuntivo - Custodia Lite Profile

## 1. Scopo e contesto

Questo documento descrive **Custodia Lite Profile**, una configurazione minimale del medesimo codice sorgente di Custodia. Non introduce un fork Lite/FULL e non introduce un secondo vocabolario di configurazione.

La versione Lite serve a eseguire Custodia su una singola macchina, VM o container, con dipendenze esterne ridotte al minimo, mantenendo i principi architetturali già definiti nella versione FULL:

- mTLS obbligatorio sulle API `/v1/*`;
- ciphertext, envelope e metadata crittografici sempre opachi per il server;
- autorizzazione granulare lato server;
- Web UI/MFA secondo il modello già implementato nella baseline FULL;
- audit integrity locale secondo il modello già implementato;
- upgrade verso FULL tramite configurazione, non tramite fork di codice.

La differenza principale è operativa: Lite usa default più semplici e disabilita i componenti enterprise esterni, ma non cambia il modello dati di sicurezza.

## 2. Principi non negoziabili

1. **Un solo codice sorgente**: `custodia-server`, `custodia-signer`, `vault-admin`, SDK e web endpoints restano comuni.
2. **Un solo vocabolario config**: niente `CUSTODIA_DB_TYPE`, `CUSTODIA_LISTEN_API`, `CUSTODIA_MFA_ENABLED` o alias paralleli. Lite e FULL usano le variabili già presenti o nuove variabili coerenti con esse.
3. **Lite è un profilo di default, non un prodotto diverso**.
4. **Nessuna regressione sicurezza**: Lite non disattiva versioning logico, audit integrity, crypto boundary, mTLS o Web UI/MFA già implementati.
5. **SQLite solo in Lite**: `sqlite` è uno store da aggiungere per installazioni single-node e non è target FULL/HA.
6. **YAML `--config` per Lite e FULL**: il file YAML popola la stessa struttura di configurazione usata dalle variabili d'ambiente; le variabili env restano utili per override e secret injection.

## 3. Profili di deployment

### 3.1 `CUSTODIA_PROFILE=lite`

Default consigliati:

```text
CUSTODIA_PROFILE=lite
CUSTODIA_STORE_BACKEND=sqlite
CUSTODIA_DATABASE_URL=file:/var/lib/custodia/custodia.db
CUSTODIA_RATE_LIMIT_BACKEND=memory
CUSTODIA_DEPLOYMENT_MODE=lite-single-node
CUSTODIA_DATABASE_HA_TARGET=none
CUSTODIA_WEB_PASSKEY_ENABLED=false
CUSTODIA_SIGNER_KEY_PROVIDER=file
```

Componenti esterni disabilitati di default:

- Valkey cluster;
- PostgreSQL/CockroachDB;
- k3s/CockroachDB rehearsal;
- MinIO/S3 Object Lock shipment;
- PKCS#11/HSM;
- WebAuthn/passkey;
- external assertion verifier;
- production evidence gates obbligatori.

Componenti che restano attivi o disponibili:

- API mTLS;
- Web UI/MFA secondo il modello FULL già implementato;
- audit chain locale;
- audit export/verify;
- strong revocation/versioning logico;
- `vault-admin` con i comandi realmente implementati;
- setup manuale tramite certificati/CA secondo il flusso già presente.

### 3.1.1 Dipendenze esterne nel profilo Lite

Lite deve funzionare senza servizi esterni obbligatori. Per “senza mondo esterno” si intende: nessuna dipendenza runtime da database di rete, cache, HSM, WORM/SIEM, k3s, MinIO o verifier WebAuthn esterno. Restano ovviamente necessari:

- client CLI/SDK o browser;
- filesystem locale per SQLite, audit e certificati;
- rete locale/TLS per esporre API e Web UI;
- backup locale/offline configurato dall'operatore.

Matrice default Lite:

| Componente esterno | Default Lite | Nota |
| --- | --- | --- |
| PostgreSQL/CockroachDB | Off | SQLite locale. |
| Valkey/Redis | Off | Rate limit memory. |
| HSM/PKCS#11/SoftHSM | Off | CA locale provider file. |
| S3 Object Lock/WORM/SIEM | Off | Audit chain locale + export/verify. |
| k3s/Cockroach rehearsal | Off | Solo FULL/lab. |
| WebAuthn external verifier | Off | TOTP default. |
| Production/evidence gates | Off by default | Disponibili come check manuali, non runtime dependency. |

### 3.2 `CUSTODIA_PROFILE=full`

Default consigliati:

```text
CUSTODIA_PROFILE=full
CUSTODIA_STORE_BACKEND=postgres
CUSTODIA_RATE_LIMIT_BACKEND=valkey
CUSTODIA_DEPLOYMENT_MODE=production
CUSTODIA_DATABASE_HA_TARGET=<real-target>
CUSTODIA_SIGNER_KEY_PROVIDER=pkcs11
```

In FULL le opzioni enterprise sono attivabili/disattivabili, ma non tutte sono equivalenti dal punto di vista production readiness. Il codice può permettere `false`, mentre `vault-admin production check` deve distinguere tra:

- configurazione ammessa per sviluppo/lab;
- configurazione ammessa ma con warning;
- configurazione vietata per produzione.

### 3.3 `CUSTODIA_PROFILE=custom`

Profilo esplicito per installazioni intermedie, ad esempio:

- SQLite + passkey off + audit local;
- PostgreSQL mononodo + rate limit memory;
- PostgreSQL + Valkey ma senza WORM;
- FULL con WebAuthn adapter esterno disattivato per ambienti interni.

`custom` non deve abbassare i requisiti fondamentali: mTLS, crypto boundary, audit integrity e Web UI/MFA restano invarianti.

## 4. Configurazione YAML comune a Lite e FULL

`custodia-server` deve supportare:

```bash
custodia-server --config /etc/custodia/config.yaml
```

Regola proposta:

1. carica default derivati da `CUSTODIA_PROFILE`;
2. carica YAML se `--config` è presente;
3. applica override da variabili d'ambiente;
4. valida config finale.

### 4.1 Esempio Lite YAML

```yaml
profile: lite

api_addr: ":8443"
web_addr: ":9443"

store_backend: sqlite
database_url: file:/var/lib/custodia/custodia.db

rate_limit_backend: memory
web_mfa_required: true
web_passkey_enabled: false

deployment_mode: lite-single-node
database_ha_target: none

client_ca_file: /etc/custodia/client-ca.crt
client_crl_file: /etc/custodia/client.crl.pem
tls_cert_file: /etc/custodia/server.crt
tls_key_file: /etc/custodia/server.key

signer_key_provider: file
signer_ca_cert_file: /etc/custodia/ca.crt
signer_ca_key_file: /etc/custodia/ca.key
```

### 4.2 Esempio FULL YAML

```yaml
profile: full

api_addr: ":8443"
web_addr: ":9443"

store_backend: postgres
database_url: postgresql://custodia@cockroachdb-public.custodia-db.svc.cluster.local:26257/custodia?sslmode=require

rate_limit_backend: valkey
valkey_url: rediss://valkey.example.com:6379/0

deployment_mode: production
database_ha_target: cockroachdb-multi-region
audit_shipment_sink: s3-object-lock://custodia-audit-prod

web_mfa_required: true
web_passkey_enabled: true
web_passkey_assertion_verify_command: /usr/local/bin/verify-passkey-assertion

signer_key_provider: pkcs11
signer_pkcs11_sign_command: /usr/local/bin/custodia-pkcs11-sign
```

## 5. SQLite store solo Lite

SQLite va aggiunto come store reale ma limitato al profilo Lite/single-node.

Configurazione proposta:

```text
CUSTODIA_STORE_BACKEND=sqlite
CUSTODIA_DATABASE_URL=file:/var/lib/custodia/custodia.db
```

Requisiti implementativi:

- stesso modello logico già presente in FULL;
- niente schema Lite ridotto;
- niente `secret_access` senza versione;
- niente disattivazione del versioning logico;
- WAL mode;
- busy timeout;
- foreign keys attive;
- migration SQLite dedicate ma semanticamente equivalenti;
- test store parity su memory/postgres/sqlite dove possibile;
- backup documentato tramite `sqlite3 .backup`.

SQLite non è target HA, non usa load balancer e non deve essere promosso a FULL.

## 6. Web UI e MFA

Lite usa quanto già implementato per FULL.

Non introdurre un modello alternativo `HTTPS + JWT only` come default Lite. Se in futuro serve una modalità semplificata, deve essere un flag esplicito e documentato come trade-off.

Default Lite:

```text
CUSTODIA_WEB_MFA_REQUIRED=true
CUSTODIA_WEB_PASSKEY_ENABLED=false
```

FULL può abilitare passkey/WebAuthn:

```text
CUSTODIA_WEB_PASSKEY_ENABLED=true
CUSTODIA_WEB_PASSKEY_ASSERTION_VERIFY_COMMAND=/usr/local/bin/verify-passkey-assertion
```

## 7. Audit

Lite non deve degradare l'audit a “JSON non firmato”.

Default Lite:

- audit chain locale secondo quanto già implementato;
- audit export/verify disponibili;
- archive/shipment WORM disattivati di default;
- S3 Object Lock/MinIO attivabili solo se configurati.

FULL:

- audit archive;
- audit shipment filesystem/S3 Object Lock;
- WORM/SIEM evidence gate;
- release/evidence artifacts.

## 8. CA e signer

Lite usa una CA locale/self-managed tramite provider file.

Default Lite:

```text
CUSTODIA_SIGNER_KEY_PROVIDER=file
```

FULL può usare:

```text
CUSTODIA_SIGNER_KEY_PROVIDER=pkcs11
```

oppure il bridge comando PKCS#11/SoftHSM per sviluppo e test.

SoftHSM resta profilo dev/test. In produzione il gate deve richiedere evidenza HSM/PKCS#11/TPM reale.

### 8.1 Utility CA locale per Lite

Fase 4 deve prevedere una utility esplicita per bootstrap Lite, senza reintrodurre comandi fittizi nella documentazione. Nome proposto:

```text
vault-admin setup lite
```

oppure, se si preferisce separare il bootstrap CA dai file di configurazione:

```text
vault-admin ca bootstrap-local
```

La utility deve generare almeno:

- CA locale self-signed;
- certificato TLS server;
- certificato client admin iniziale;
- CRL locale vuota;
- `config.lite.yaml`;
- permessi file restrittivi;
- istruzioni di backup/offline della CA.

### 8.2 Passphrase CA opzionale

La passphrase della chiave CA locale deve essere supportata come opzione Fase 4, non promessa come feature già esistente finché non viene implementata nel file provider.

Regola proposta:

```text
Lite default tecnico: CA file locale.
Lite best practice: CA key cifrata con passphrase o conservata offline.
Full production: PKCS#11/HSM con evidenza reale.
```

Config proposta, coerente col vocabolario esistente:

```text
CUSTODIA_SIGNER_CA_KEY_FILE=/etc/custodia/ca.key
CUSTODIA_SIGNER_CA_KEY_PASSPHRASE_FILE=/etc/custodia/ca.pass
```

`PASSPHRASE_FILE` è preferibile a una variabile env contenente il segreto, perché evita leak in process list, shell history e dump ambienti. Se non è configurato, il provider file può accettare chiavi non cifrate solo per sviluppo/lab o con warning esplicito.

## 9. CLI e setup

Il documento Lite deve citare solo comandi realmente presenti nel repo.

Non introdurre:

```bash
custodia-server setup --ca --output /etc/custodia
vault-admin secret decrypt
vault-admin export --format sqlite
```

finché non vengono implementati.

Per Fase 4 si può aggiungere in seguito un helper:

```text
vault-admin setup lite
```

ma va trattato come blocco dedicato, non come funzionalità già esistente.

## 10. Rate limiting e cache

Lite:

```text
CUSTODIA_RATE_LIMIT_BACKEND=memory
```

FULL:

```text
CUSTODIA_RATE_LIMIT_BACKEND=valkey
CUSTODIA_VALKEY_URL=rediss://...
```

La cache esterna resta disattivata in Lite. Il limite non è condiviso tra istanze, ma questo è coerente con single-node.

## 11. Revoca certificati

Lite può funzionare con controllo applicativo `is_active` e CRL file locale se configurato.

FULL può attivare:

- CRL distribution;
- revocation serial responder;
- OCSP/evidence drill se disponibile;
- production revocation evidence gate.

Non dichiarare OCSP completo finché non esiste un responder RFC 6960 binario firmato.

## 12. Evoluzione Lite -> FULL

La migrazione deve essere principalmente configurativa:

1. `profile: lite` -> `profile: custom` o `profile: full`;
2. `store_backend: sqlite` -> `postgres`;
3. migrazione dati SQLite -> PostgreSQL/Cockroach con tool dedicato da implementare;
4. `rate_limit_backend: memory` -> `valkey`;
5. `signer_key_provider: file` -> `pkcs11`;
6. `web_passkey_enabled: false` -> `true`;
7. audit local -> S3 Object Lock/WORM shipment;
8. production/evidence gates obbligatori.

La migrazione SQLite -> PostgreSQL richiede un tool dedicato futuro. Non usare `sqlite3 .dump` come procedura consigliata production.

## 13. Fase 4 proposta

### Blocco A - documento Lite allineato

Questo documento sostituisce la versione iniziale e definisce i confini corretti.

### Blocco B - config YAML comune

- `--config` su `custodia-server`;
- YAML loader;
- env override;
- test precedence;
- esempi Lite/FULL.

### Blocco C - profili

- `CUSTODIA_PROFILE=lite|full|custom`;
- default derivati dal profilo;
- validation matrix;
- production check aggiornato.

### Blocco D - SQLite store

- `internal/store/sqlite`;
- migration SQLite;
- WAL/busy timeout/foreign keys;
- store parity tests;
- backup docs.

### Blocco E - packaging Lite

- `.env.lite.example`;
- `config.lite.yaml`;
- systemd unit example;
- Docker Compose single-node Lite;
- runbook installazione.

Il runbook Lite deve includere consigli di sicurezza espliciti:

- usare utente di sistema dedicato `custodia`;
- proteggere `/etc/custodia` con permessi restrittivi;
- usare passphrase CA o CA offline quando possibile;
- abilitare backup SQLite con `sqlite3 .backup`;
- abilitare audit export/verify periodico;
- non esporre API/Web UI direttamente su Internet senza reverse proxy/TLS hardening e firewall;
- ruotare certificato admin iniziale dopo bootstrap;
- documentare procedura di disaster recovery single-node.

### Blocco F - upgrade path

- docs Lite -> FULL;
- migration planning;
- production readiness/evidence gates.

## 14. Cosa FULL può attivare/disattivare

FULL è modulare, ma non arbitrario.

| Componente | FULL può disattivarlo? | Nota |
| --- | --- | --- |
| mTLS API | No | Requisito fondamentale. |
| Crypto boundary opaque | No | Requisito fondamentale. |
| Audit integrity | No | Requisito fondamentale. |
| Web MFA | No in production | Può variare metodo, non assenza. |
| PostgreSQL/Cockroach | Sì, solo custom/lab | FULL production richiede store production-grade. |
| Valkey rate limit | Sì con warning | Production check deve segnalare downgrade. |
| WORM/SIEM shipment | Sì con warning/error in production | Dipende dal profilo. |
| HSM/PKCS#11 | Sì in custom/lab | FULL production deve richiedere evidenza reale. |
| WebAuthn/passkey | Sì | TOTP resta fattore minimo. |
| k3s/Cockroach rehearsal | Sì | È rehearsal, non production obbligatoria. |
| MinIO Object Lock | Sì | È dev/test o S3-compatible target, non requisito universale. |

## 15. Documentazione Lite da produrre

Fase 4 deve produrre documentazione operativa dedicata, non solo questa specifica:

- `docs/LITE_INSTALL.md`: installazione sicura single-node;
- `docs/LITE_CONFIG.md`: mapping YAML/env dei profili `lite`, `full`, `custom`;
- `docs/LITE_CA_BOOTSTRAP.md`: CA locale, passphrase opzionale, backup/offline e rotazione manuale;
- `docs/LITE_BACKUP_RESTORE.md`: backup SQLite, audit export e restore;
- `docs/LITE_TO_FULL_UPGRADE.md`: percorso SQLite -> PostgreSQL/Cockroach, file signer -> PKCS#11, audit local -> WORM/SIEM.

La documentazione deve indicare chiaramente cosa è default, cosa è consigliato e cosa è richiesto solo in FULL production.

## 16. Conclusione

Custodia Lite è una buona Fase 4 se resta un **profilo configurabile dello stesso prodotto**.

La direzione corretta è:

```text
same codebase
same config vocabulary
SQLite only for Lite
same security model
same logical schema
YAML config shared by Lite/FULL
profile-driven defaults
feature flags explicit
production gates for FULL
```

La versione Lite deve essere più semplice da installare, non meno corretta dal punto di vista sicurezza.
