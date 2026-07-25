# Capshell

**Il posto dove le tue chiavi API non entrano mai nel container.**

Capshell è un daemon che tiene le credenziali delle API LLM fuori dai container in
cui giri agenti AI autonomi (OpenHands, Claude Code, script LLM). L'agente riceve
un token finto e un endpoint locale; la chiave vera resta sull'host, in RAM, e non
attraversa mai il confine.

> **Stato: progettazione.** Nessuna riga di codice è ancora stata scritta.
> Questo documento definisce direzione, perimetro e proprietà da dimostrare.
> Non è software di sicurezza auditato: fino a revisione indipendente, usare solo
> credenziali di test.

---

## Il problema

Un agente autonomo che lavora sul tuo codice ha bisogno di chiamare API a
pagamento. Il modo standard di dargliene accesso è mettere la chiave in una
variabile d'ambiente — e a quel punto qualunque processo dentro quell'ambiente
può leggerla, copiarla, spedirla altrove. Non è un bug: è il comportamento
corretto di Unix.

Il masking non risolve: sostituisce rappresentazioni letterali note, e viene
aggirato da encoding, frammentazione, filesystem e rete.

Il primitivo stesso — *"il segreto è una stringa disponibile al processo"* — è
incompatibile con la richiesta di proteggere il segreto **dal** processo.

---

## Cosa fa Capshell

Capshell **non crea il sandbox**. Quello lo fa già il tuo container runtime.
Capshell sta fuori dal sandbox e fa quattro cose:

1. Tiene le chiavi vere in RAM sull'host, caricate da un canale fidato.
2. Espone un **proxy HTTP a rotte statiche**: l'agente parla con `localhost`,
   Capshell inietta la chiave vera e inoltra a un upstream **cablato**.
3. Applica un **budget** per sessione, contato prima dell'inoltro, fail-closed.
4. Genera l'**environment mockato** da passare al container e verifica, prima di
   avviarlo, che nessun valore reale sia raggiungibile dall'agente.

```
┌─ host (fidato) ─────────────────────────────┐
│  capshell daemon                            │
│   • chiavi vere in RAM (mlock)              │
│   • proxy L7, rotte statiche                │
│   • budget counter (richieste + byte)       │
│   • startup gate                            │
└────────────────────┬────────────────────────┘
                     │  una porta / un socket
┌────────────────────▼────────────────────────┐
│  il TUO container (Docker, podman,          │
│  devcontainer, qualunque cosa)              │
│   • OPENAI_BASE_URL=http://…/openai         │
│   • OPENAI_API_KEY=<mock>                   │
│   • nessuna chiave reale                    │
└─────────────────────────────────────────────┘
```

### Perché sidecar e non runtime

L'isolamento di filesystem, processi e rete è un problema risolto: lo fanno
Docker, podman, i devcontainer. Reimplementarlo con `bwrap`, OverlayFS e user
namespace significa moltiplicare superficie di attacco e codice privilegiato per
riottenere qualcosa che l'utente ha già.

La conseguenza è un prodotto molto più piccolo — e adottabile senza cambiare
workflow: chi già containerizza l'agente cambia due variabili d'ambiente.

---

## Tassonomia dei segreti

| Classe | Tipo | Meccanismo | Garanzia |
|---|---|---|---|
| **Bearer token HTTP** (OpenAI, Anthropic, endpoint OpenAI-compatible) | `proxied` | chiave in RAM sull'host, mock nel container, proxy con upstream fisso | il valore non entra mai nel container; l'uso è limitato a un endpoint e a un budget |
| **Request signing** (AWS SigV4) e **client rigidi** (Stripe) | *fuori scope v0* | — | richiedono un proxy protocol-aware che ricalcoli le firme, o SDK che non accettano override del base URL da env |
| **Database TCP** e **chiavi crittografiche locali** (Postgres, Redis, `DJANGO_SECRET_KEY`) | `passthrough` | forniti in chiaro nell'environment del container, se dichiarati esplicitamente | **nessuna**: il valore è nel dominio dell'agente per scelta. Vedi sotto. |

### Sul `passthrough`

Capshell è il componente che *consegna* quel valore all'agente. Non è un
incidente inarginabile: è una scelta, dichiarata segreto per segreto, con warning
esplicito. L'assunzione è che nell'ambiente isolato girino servizi di
dev/staging effimeri.

Nota operativa: **la rete del container decide l'impatto reale.** Se il container
non ha egress libero, una credenziale `passthrough` può essere letta ma non
usata contro nulla di raggiungibile. Con egress libero, può essere usata. Se
dichiari `passthrough`, restringi la rete del container — è l'unico caso in cui
l'isolamento di rete è portante (vedi *Precondizioni*).

---

## Le proprietà da dimostrare

Quattro proprietà, verificate da test. Non sono dimostrazioni formali: sono
condizioni di accettazione, che una suite rende verdi o rosse.

### INV-SECRET — il valore non esiste nel dominio dell'agente

> Per ogni segreto dichiarato `proxied`, il valore non compare in nessun punto
> osservabile dall'agente.

Non è garantito da un singolo meccanismo. Richiede **quattro controlli in quattro
momenti**:

1. **Mask** — i file che contengono i segreti dichiarati non vengono montati nel
   container; al loro posto Capshell genera la versione mockata.
2. **Startup gate** — scansione ricorsiva di ciò che il container monterà, alla
   ricerca dei valori reali (in chiaro e in base64). Trovarne uno — una chiave
   committata per errore, un `.env.local` dimenticato, un `terraform.tfvars` —
   **aborta l'avvio**. Il gate gira *dopo* la generazione del mock, non prima:
   deve poter cogliere anche un errore di generazione.
3. **Environment check** — l'environment effettivo passato al container viene
   verificato al lancio, non dedotto.
4. **No reflection** — il proxy non riflette mai la richiesta upstream verso il
   client, in nessun path di errore. I body di errore upstream sono troncati e
   filtrati.

Il mask senza il gate è una denylist, e le denylist perdono. Il gate senza il
mask aborta sul setup più comune che esista — la chiave nel `.env` del progetto.
Servono entrambi.

**Test:** canary al posto della chiave vera; scansione di environment, filesystem
visibile all'agente, stdout/stderr, log e audit del daemon. Zero occorrenze.

### INV-DEST — la destinazione è cablata, non negoziabile

> Nessun input dell'agente può far arrivare una richiesta autenticata a un host
> diverso da quello dichiarato nel connector.

Le rotte sono statiche: `/openai` parla con `api.openai.com` e con nient'altro.
Non esiste un proxy generico.

**Test (tutti devono essere respinti o forzati sull'host fisso):** header `Host`
ostile; request line con URI assoluto; metodo `CONNECT`; `X-Forwarded-Host`,
`X-Original-URL`; path traversal; **e i redirect `3xx` dall'upstream — il proxy
non li segue, e non riallega mai la chiave a una destinazione derivata da una
risposta.**

Senza questo invariante il proxy non è un muro: è un tunnel di esfiltrazione
autenticato.

### INV-BUDGET — la spesa è limitata e fallisce chiusa

> Superato il limite dichiarato per la sessione, ogni richiesta successiva è
> rifiutata localmente.

Due contatori, entrambi necessari:

- **numero di richieste** — copre i loop infiniti;
- **byte inviati upstream** — il numero di richieste è un proxy debole per il
  costo: 500 chiamate con contesto pieno valgono centinaia di dollari. I byte
  sono provider-agnostici, banali da contare, e correlano molto meglio.

Il contatore si incrementa **prima** dell'inoltro, non dopo: con richieste
concorrenti, `forward-then-count` lascia passare più di N. Se il componente di
accounting fallisce, la richiesta è negata.

Questo è l'invariante che difende la tesi economica. Una chiave illeggibile non
protegge il conto: l'agente non legge `sk-…`, ma può comunque usare il proxy come
oracolo finché non lo fermi.

Il calcolo del costo per-token, specifico per provider, è rimandato: v0 usa
contatori grezzi.

### INV-UID — precondizione, non meccanismo

> Il processo agente gira in un PID namespace separato e sotto un UID kernel
> diverso da quello del daemon.

Capshell **non implementa** questo isolamento — lo fa il container runtime. Lo
**verifica**: il daemon rifiuta di servire un client che non risulti isolato, e
lo dichiara all'avvio.

Serve perché `mlock` impedisce lo swap, non la lettura: senza separazione di UID,
un processo potrebbe leggere la memoria del daemon con `ptrace` e prendersi la
chiave.

**Test:** dal container, `ps` non vede il daemon; `cat /proc/<pid>/mem`, `gdb -p`
e `ptrace` restituiscono `Permission Denied`.

---

## Precondizioni

Capshell assume che l'ambiente fornisca:

- **Isolamento di processo** — l'agente in un container o namespace separato, con
  UID diverso da quello del daemon. Verificato all'avvio, non creato da Capshell.
- **Un canale fidato per caricare i segreti** — TTY con echo disabilitato o
  keyring. **Mai dal file di configurazione.**
- **Isolamento di rete, solo se usi `passthrough`** — altrimenti opzionale. Per i
  segreti `proxied` non è portante: l'agente non ha la chiave, quindi anche con
  egress libero non può usarla se non passando dal proxy, dove il routing è fisso
  e il budget conta.

---

## Configurazione

Il file dichiara **nomi, tipi e connector**. Non contiene valori: altrimenti
avresti creato un nuovo file di segreti che vive nel progetto, finisce in git, e
vanifica il resto del design.

```yaml
# capshell.yaml
secrets:
  - name: OPENAI_API_KEY
    type: proxied
    connector: openai        # upstream cablato: api.openai.com

  - name: ANTHROPIC_API_KEY
    type: proxied
    connector: anthropic

  - name: POSTGRES_PASSWORD
    type: passthrough        # in chiaro nel container, per scelta dichiarata

budget:
  max_requests: 500
  max_upstream_bytes: 50MiB
```

I valori si caricano a parte:

```bash
capshell secret load OPENAI_API_KEY   # letto da TTY con echo disabilitato
capshell up                           # avvia il daemon, esegue mask + gate
```

---

## Fuori scope

Esplicitamente **non** obiettivi di questo progetto:

- **Isolamento di filesystem, processi e rete** — è del container runtime.
- **Protezione del codice sorgente dall'esfiltrazione.** Un agente con accesso a
  un endpoint LLM può codificare dati in un prompt. Non è arginabile e non lo
  promettiamo.
- **Riapplicazione delle modifiche dell'agente sull'host** (`apply`, diff,
  workspace effimeri, OverlayFS). Lo risolve Docker.
- **Git secretless, push brokerato, validazione delle patch.**
- **AWS SigV4 e client senza override del base URL** (Stripe). Rimandati a M1.
- **Protezione da root, exploit del kernel, attacchi fisici, compromissione del
  provider upstream.**
- **macOS e Windows.** Linux-first.

---

## Cosa resta possibile a un agente malevolo

Sotto il modello dichiarato, l'agente può ancora:

- consumare il budget fino al limite che hai concesso;
- esfiltrare codice e dati attraverso l'endpoint LLM consentito;
- usare e far trapelare qualunque credenziale dichiarata `passthrough`;
- sfruttare un bug in Capshell, nel container runtime o nel kernel;
- produrre codice malevolo, che è un problema di chi lo rivede.

Quello che **non** può fare è ottenere il valore di una chiave `proxied`, usarla
verso una destinazione che non hai dichiarato, o spendere oltre il limite che hai
fissato.

---

## Roadmap

**v0** — un daemon, proxy a rotte statiche per provider LLM bearer-token,
budget grezzo, mock env, mask + startup gate, le quattro proprietà con la loro
suite di test.

**M1** — connector protocol-aware: AWS SigV4 con re-signing, provider con SDK che
non accettano override da env. Costo per-token invece dei contatori grezzi.

**M2** — keyring persistente, credenziali a vita breve (GitHub App, OIDC, STS),
connector per registry di pacchetti autenticati.

**M3** — sessioni multiple, audit strutturato, `capshell run` con `bwrap` come
convenienza per chi non containerizza — mai come nucleo.

Ogni fase mantiene i fallback espliciti e non indebolisce in silenzio le garanzie
già dichiarate.

---

## Linguaggio

Il nucleo — proxy, parser della configurazione, gestione della memoria dei
segreti — è codice che tratta input ostile mentre custodisce credenziali.
Indirizzo: **Rust**. La superficie è piccola (nessun runtime async necessario per
v0) e le classi di bug che Rust elimina per costruzione sono esattamente quelle
che in un componente del genere diventano CVE.

---

## Sulle affermazioni

Questo documento evita deliberatamente "100% sicuro", "rischio zero" e
"matematicamente verificabile". Le quattro proprietà sopra sono **condizioni
testabili**, non teoremi: una suite di test non è una dimostrazione. Il valore del
progetto sta nell'averle scritte in modo che un test possa smentirle.
