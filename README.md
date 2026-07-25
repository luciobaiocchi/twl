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

budget:                      # opzionale, assente per default
  max_requests: 500
```

Qualunque variabile presente nella sorgente e non dichiarata in `capshell.yaml`
viene passata al figlio **invariata**. Capshell non indovina: tocca solo ciò che
gli dici di toccare.

### Il limite di consumo è opzionale

Senza il blocco `budget`, Capshell impedisce che la chiave venga **rubata**, non
che venga **usata**: l'agente può chiamare l'endpoint dichiarato finché la
sessione vive. È comunque una differenza reale — una chiave esfiltrata è per
sempre, un accesso brokerato muore con la sessione — ma va detta.

Con `max_requests`, la richiesta N+1 viene rifiutata localmente. Il contatore si
incrementa **prima** dell'inoltro: con richieste concorrenti, contare dopo lascia
passare più di N.

---

## Da dove arrivano i segreti

La sorgente è un backend intercambiabile, scelto in base all'ambiente. La
garanzia non cambia: il valore entra nella memoria di Capshell e il figlio riceve
sempre e solo il mock.

| ambiente | sorgente |
|---|---|
| host desktop (macOS, Windows, Linux con sessione) | **OS keyring** |
| container, headless, CI | **environment del processo Capshell**, iniettato dal runtime |
| primo avvio / migrazione | `--env .env` non committato |

I due ambienti si coprono a vicenda: il keyring è facile sull'host e impossibile
in un container; la separazione di UID è gratis in un container e costosa
sull'host.

> Il keyring arriva in M1. La v0 usa `--env` sull'host e l'environment del
> processo negli ambienti containerizzati.

### Il `.env` non è una modalità, è un percorso di migrazione

```bash
capshell secret import .env
```

Sposta i valori nel keyring e riscrive il `.env` con i placeholder. Da quel
momento il file non contiene più segreti e può anche finire in git senza danni.
`--env` resta per il primo avvio e per chi un keyring non ce l'ha.

### Nel container

Vale un principio unico:

> **Capshell e l'agente devono essere separati da qualcosa: un UID, un container
> o una macchina.** Se condividono UID e namespace, non c'è niente da proteggere.

In ordine di preferenza:

1. **Due container** — Capshell in uno, l'agente nell'altro, che parla col proxy
   sulla rete interna. Nessun privilegio, nessun namespace condiviso, dieci righe
   di compose. È il pattern sidecar con entrambi containerizzati.
2. **Un container, due UID** — Capshell parte come root e spawna il figlio sotto
   un utente non privilegiato. La sequenza è `setgroups()` → `setgid()` →
   `setuid()`, **in quest'ordine**; poi si verifica che il drop sia avvenuto e si
   fallisce chiuso in caso contrario, si chiudono i descrittori ereditati con
   `close_range()`, e solo allora `execve()`.
3. **Un container, un UID** — sopravvivibile ma con una difesa sola, e non è la
   modalità consigliata. Regge su `prctl(PR_SET_DUMPABLE, 0)`: contro un processo
   non-dumpable il kernel richiede `CAP_SYS_PTRACE` per leggere `environ`, `mem`
   e `maps`, anche a parità di UID. Perché funzioni servono due condizioni: il
   segreto arriva dall'environment e **non** da un file leggibile dall'agente, e
   Capshell è l'**entrypoint** — se lo lancia uno script di shell, quello resta
   vivo come PID 1 con il segreto nel proprio `environ`.

   Yama non basta da solo: `ptrace_scope` filtra `PTRACE_MODE_ATTACH`, mentre la
   lettura di `/proc/<pid>/environ` passa da `PTRACE_MODE_READ`. È `dumpable=0` a
   chiudere entrambe le vie.

### Non-goal: cifratura a riposo

Capshell **non persiste niente**. Legge la sorgente all'avvio, tiene il valore in
memoria per la durata del processo, e muore con esso. Non esiste un "at rest" da
cifrare, quindi non esiste un cifrario da scegliere, una chiave di cifratura da
custodire, né un file di stato da proteggere.

Se un giorno servisse persistere segreti su disco, la risposta giusta non è
aggiungere un cifrario: è usare il keyring, o iniettarli a runtime.

---

## Piattaforme

Il nucleo — processo figlio, environment mockato, proxy locale — è **puro
POSIX**: funziona su Linux e macOS senza namespace, container o privilegi.

Non è previsto un confinamento del filesystem costruito da Capshell. Un mount
namespace servirebbe solo a nascondere al figlio il file da cui i segreti
arrivano — un problema che il keyring elimina alla radice, e che nel frattempo
`PR_SET_DUMPABLE` copre per la sorgente da environment. Chi vuole confinare
davvero il filesystem usa Docker, che lo fa meglio e che è già nel percorso
consigliato.

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

**M2 — controllo del consumo, oltre il contatore.** Il cap sulle richieste c'è
già in v0. Restano da fare i byte inviati upstream e il costo per-token
provider-specific: il numero di chiamate è un proxy debole per la spesa, 500
richieste con contesto pieno valgono centinaia di dollari.

**M3 — copertura.** Connector protocol-aware (AWS SigV4, client senza override
del base URL come Stripe). Scansione pre-flight dei segreti committati per errore
nel repository — problema di igiene di git più che di agenti, ma facile da
segnalare quando si è già lì.

Ogni fase mantiene fallback espliciti e non indebolisce in silenzio le garanzie
già dichiarate.

---

## Cosa resta possibile a un agente malevolo

- **Usare** la chiave attraverso il proxy, verso l'endpoint dichiarato, finché
  la sessione vive — senza limite, se non configuri `budget`.
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
