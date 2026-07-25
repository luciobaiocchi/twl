# Capshell

**L'agente non vede le tue chiavi API. Un comando.**

```bash
capshell run --env .env -- codex
```

Capshell avvia il tuo agente (Codex, Claude Code, OpenHands, uno script) come
processo figlio con un environment in cui le chiavi vere sono sostituite da
token finti. Le chiavi reali restano nel processo padre, in memoria, e vengono
attaccate alle richieste solo da un proxy locale con destinazione cablata.

> **Stato: progettazione.** Nessuna riga di codice scritta.
> Non è software di sicurezza auditato: fino a revisione indipendente, usare
> solo credenziali di test.

---

## Il problema

Dare a un agente autonomo una chiave API significa metterla in una variabile
d'ambiente, e a quel punto qualunque processo in quell'ambiente può leggerla e
spedirla altrove. Non è un bug: è Unix che funziona correttamente.

Il masking non risolve — sostituisce stringhe letterali note, e viene aggirato
da encoding, frammentazione, file e rete. Il primitivo stesso, *"il segreto è
una stringa disponibile al processo"*, è incompatibile con il proteggere il
segreto **dal** processo.

---

## Come funziona

Tre passi, nessuna configurazione oltre a un file.

1. **Capshell legge i segreti veri** da una sorgente che l'agente non vede.
2. **Genera un environment mockato** e ci lancia dentro il processo figlio:
   `OPENAI_API_KEY=cs-mock-…`, `OPENAI_BASE_URL=http://127.0.0.1:PORT/openai`.
3. **Espone un proxy locale a rotte statiche.** Alla richiesta dell'agente
   sostituisce il mock con la chiave vera e inoltra a un upstream cablato.

### Perché l'agente non può semplicemente chiamare OpenAI

Perché non ha niente da usare. Il token che possiede è finto: una chiamata
diretta ad `api.openai.com` risponde `401`. L'unico percorso che funziona passa
dal proxy, dove la chiave viene attaccata da Capshell e la destinazione è decisa
da Capshell.

Non stai vietando all'agente di uscire. Stai facendo in modo che uscire da solo
non gli serva a niente.

---

## Cosa è, e cosa non è

Capshell fa **una cosa**: impedisce che il valore di una chiave API entri nel
processo dell'agente. Tutto il resto è delegato a strumenti che esistono già e
funzionano meglio.

| | |
|---|---|
| L'agente ti distrugge la codebase? | **Usa git.** Non è un problema di Capshell. |
| Vuoi isolamento vero di processi e filesystem? | **Usa Docker.** Capshell ci gira dentro senza modifiche. |
| Vuoi impedire l'esfiltrazione del codice sorgente? | **Non è possibile** con un endpoint LLM raggiungibile. Non lo promettiamo. |
| L'agente consuma troppi token? | Fuori scope v0. Vedi roadmap. |

---

## Le due proprietà

Condizioni testabili, non teoremi. Una suite di test le rende verdi o rosse.

### INV-SECRET — il valore non entra nel processo agente

> Per nessun segreto gestito il valore reale compare nell'environment del
> processo figlio, dei suoi discendenti, nel suo stdout/stderr, o nei log.

Include una regola sul proxy: **non riflette mai la richiesta upstream verso il
client**, in nessun path di errore. I body di errore upstream vengono troncati e
filtrati, altrimenti l'header iniettato può tornare indietro all'agente.

**Test:** canary al posto della chiave vera, scansione di environment
(`/proc/<pid>/environ` di ogni discendente), output e log. Zero occorrenze, in
chiaro e in base64.

### INV-DEST — la destinazione è cablata

> Nessun input dell'agente può far arrivare una richiesta autenticata a un host
> diverso da quello del connector.

`/openai` parla con `api.openai.com` e con nient'altro. Non esiste un proxy
generico.

**Test — tutti respinti o forzati sull'host fisso:** header `Host` ostile;
request line con URI assoluto; `CONNECT`; `X-Forwarded-Host`, `X-Original-URL`;
path traversal; **e i redirect `3xx` dall'upstream, che il proxy non segue mai e
a cui non riallega mai la chiave.**

Senza INV-DEST il proxy non è un muro: è un tunnel di esfiltrazione autenticato.

---

## Configurazione

Un file, che dichiara **nomi, tipi e connector**. I valori non stanno qui.

```yaml
# capshell.yaml
secrets:
  - name: OPENAI_API_KEY
    connector: openai        # upstream cablato: api.openai.com
  - name: ANTHROPIC_API_KEY
    connector: anthropic
```

**Sorgente dei valori in v0:** un `.env` non committato, indicato al lancio.

```bash
capshell run --env .env -- codex
```

Qualunque variabile presente nel `.env` e non dichiarata in `capshell.yaml`
viene passata al figlio **invariata**. Capshell non indovina: tocca solo ciò che
gli dici di toccare.

---

## Piattaforme

Il nucleo — processo figlio, environment mockato, proxy locale — è **puro
POSIX**: funziona su Linux e macOS senza namespace, container o privilegi.

L'hardening del filesystem (mount namespace che nasconde al figlio il file
sorgente dei segreti) è **opzionale e Linux-only**. Non è richiesto perché il
nucleo funzioni, e diventa irrilevante quando i segreti arrivano dal keyring
invece che da un file.

---

## Roadmap

**v0 — questo documento.** Un comando, un file di config, connector per provider
LLM bearer-token (OpenAI, Anthropic, OpenAI-compatible), le due proprietà con la
loro suite di test. Sorgente segreti: `.env` non committato.

**M1 — keyring.** Integrazione con il portachiavi di sistema (Secret Service su
Linux, Keychain su macOS), con i segreti associati a un progetto e caricati
automaticamente quando lo avvii. Accessibili solo all'utente umano.

> Questa è la milestone che conta davvero. Finché la sorgente è un file su
> disco, l'agente non isolato può leggerlo e serve mascherarlo. Con il keyring
> il segreto non è in nessun file e il mascheramento diventa inutile: il keyring
> **toglie** codice al progetto invece di aggiungerne.

**M2 — controllo del consumo.** Contatore di richieste e byte per sessione,
fail-closed. Senza questo Capshell impedisce che la chiave venga *rubata*, non
che venga *usata*: la distinzione è reale (una chiave esfiltrata è per sempre,
un accesso brokerato muore con la sessione) ma va detta, non nascosta.

**M3 — copertura e hardening.** Connector protocol-aware (AWS SigV4, client
senza override del base URL come Stripe). Scansione pre-flight dei segreti
committati per errore nel repository — problema di igiene di git più che di
agenti, ma facile da segnalare quando si è già lì. Mount namespace di default su
Linux, separazione di UID.

Ogni fase mantiene fallback espliciti e non indebolisce in silenzio le garanzie
già dichiarate.

---

## Cosa resta possibile a un agente malevolo

- **Usare** la chiave attraverso il proxy, verso l'endpoint dichiarato, finché
  la sessione vive (fino a M2).
- **Esfiltrare** codice e dati codificandoli in un prompt. Non arginabile.
- **Modificare o distruggere** i file su cui lavora. Usa git.
- **Leggere altre credenziali** presenti sulla macchina, se non lo isoli.
  Usa Docker, o M1.
- Sfruttare un bug in Capshell, nel kernel, o nel provider upstream.

Quello che **non** può fare è ottenere il valore di una chiave gestita, o usarla
verso una destinazione che non hai dichiarato.

---

## Vincoli di progetto

Tre regole che decidono cosa entra e cosa no:

1. **Manutenibile da una persona.** Se una funzionalità richiede più di un
   manutentore per restare corretta, non entra.
2. **Nessun privilegio richiesto.** Niente root, niente setuid, niente daemon di
   sistema per il percorso principale.
3. **Componibile, non sostitutivo.** Capshell si affianca a Docker, git e ai
   keyring esistenti. Non li rimpiazza e non li richiede.

---

## Sulle affermazioni

Questo documento evita "100% sicuro", "rischio zero" e "matematicamente
verificabile". Le due proprietà sopra sono condizioni testabili, non
dimostrazioni: una suite di test non è una prova. Il valore sta nell'averle
scritte in modo che un test possa smentirle.
