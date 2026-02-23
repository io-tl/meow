# SynScan

Scanner de ports TCP haute performance via paquets SYN forges. Detection automatique du meilleur transport disponible (AF_PACKET, raw sockets, connect fallback). Scan deterministe avec reprise via token. Publication des ports ouverts sur NATS pour integration avec le pipeline grabber/datastore.

## Installation

```bash
go build -o synscan ./cmd/synscan/

# Permissions pour SYN scan natif (AF_PACKET / raw sockets)
sudo setcap cap_net_raw+ep ./synscan
```

## Utilisation rapide

```bash
# Scan basique
./synscan -t 192.168.1.0/24 -p 80,443

# Scan avec publication NATS
./synscan -t 192.168.1.0/24 -p 1-1000 --nats-url nats://localhost:4222 --nats-token SECRET

# Scan rapide avec rate eleve
./synscan -t 10.0.0.0/24 -p 80,443,22,8080 -r 5000

# Reprise d'un scan interrompu
./synscan -t 192.168.1.0/24 -p 80,443 --resume 17b5c7a2e6e8f5520000b128
```

Les ports ouverts sont affiches sur stdout (`ip:port`), les infos de progression sur stderr.

## Options CLI

```
  -t, --target <cidr>      Cible CIDR ou range nmap-style (requis)
  -p, --ports <ports>      Ports a scanner (defaut: 80,443,22,8080,8443)
  -i, --interface <iface>  Interface reseau (auto-detectee si vide)
  -r, --rate-limit <n>     Paquets par seconde (defaut: 1000)
      --timeout <ms>       Timeout en millisecondes (defaut: 5000)
  -c, --config <path>      Fichier config YAML (defaut: config.yaml)
      --nats-url <url>     URL du serveur NATS
      --nats-token <token> Token d'authentification NATS
      --resume <token>     Token de reprise (hex 24 chars)
  -v, --verbose            Mode verbeux (affiche ports fermes/filtres)
  -h, --help               Aide
      --version            Version
```

Le mode verbeux peut aussi etre active via `VERBOSE=1`.

### Priorite de configuration

La configuration suit cet ordre (du plus bas au plus eleve) :

1. **Valeurs par defaut** internes
2. **Fichier config.yaml** (ou fichier specifie via `--config`)
3. **Flags CLI** (priorite maximale)

## Configuration YAML

Le fichier config est compatible avec celui du grabber (sections NATS partagees).

```yaml
nats:
  url: "nats://localhost:4222"
  auth:
    token: "SECRET"

synscan:
  target:
    cidr: "192.168.1.0/24"
    ports: "80,443,22,8080,8443"
  network:
    interface: ""           # Auto-detection si vide
  performance:
    rate_limit: 1000        # Paquets par seconde
    timeout_ms: 5000        # Timeout par port (ms)

logging:
  level: "info"
  format: "console"
```

Les parametres de batch (`send: 64`, `recv: 64`, `ring_size: 4096`, `ip_batch_size: 4096`) sont des constantes internes non configurables.

## Formats de cibles (nmap-style)

Le parametre `--target` supporte plusieurs formats :

```bash
# IP unique
-t 192.168.0.1

# CIDR
-t 192.168.0.0/24                 # 254 IPs (.0 et .255 exclus pour /24+)
-t 10.0.0.0/16                    # ~65k IPs

# Range dernier octet
-t 192.168.0.1-10                 # 10 IPs

# Range multi-octets
-t 192.168.1-5.1                  # 5 IPs (192.168.1.1 ... 192.168.5.1)
-t 192.168.1-3.10-12              # 9 IPs (3 x 3)
-t 192.168-170.1-10.1-5           # 150 IPs (3 x 10 x 5)

# CIDR avec ranges
-t 192.168.1-3.0/24               # ~750 IPs (3 x 254)
```

Limite de securite : 16M IPs maximum par scan.

## Formats de ports

```bash
-p 80,443,22                      # Ports individuels
-p 1-1000                         # Range
-p 1-100,443,8000-9000,3306       # Combinaison
```

## Couche transport

Le transport est auto-detecte au demarrage selon les capacites du systeme.

### Linux

| Transport | Performance | Privileges | Methode |
|-----------|-------------|------------|---------|
| AF_PACKET | ~2M PPS | root / CAP_NET_RAW | TPACKET_V3 mmap ring buffer |
| Raw Socket | ~500K PPS | root / CAP_NET_RAW | sendmmsg / recvmmsg |
| Connect | ~50K PPS | aucun | TCP connect() fallback |

Ordre de detection : AF_PACKET > Raw Socket > Connect

### Windows

| Transport | Performance | Privileges | Methode |
|-----------|-------------|------------|---------|
| Npcap | ~500K PPS | Admin + Npcap installe | Raw injection via wpcap.dll (LazyDLL) |
| Hybrid | ~200K PPS | Admin | connect() SYN + SOCK_RAW recv |
| Connect | ~50K PPS | aucun | TCP connect() fallback |

Ordre de detection : Npcap > Hybrid > Connect

Le binaire est statique (pas de CGO). Npcap est charge via `syscall.NewLazyDLL` avec fallback gracieux.

## Reprise de scan (resume)

Chaque scan utilise un seed deterministe pour la randomisation des IPs et ports. Un token hexadecimal de 24 caracteres encode le seed et l'offset de progression :

```
Format: <seed:16hex><offset:8hex>
Exemple: 17b5c7a2e6e8f5520000b128
```

### Fonctionnement

1. Au demarrage, le token est affiche sur stderr (Scan ID)
2. En cas d'interruption (Ctrl+C), le token de reprise est affiche
3. Le scan reprend exactement ou il s'est arrete grace au meme seed

```bash
# Scan initial
./synscan -t 10.0.0.0/16 -p 1-1000

# Interruption → affiche: To resume: synscan [same flags] --resume 17b5c7a2e6e8f5520000b128

# Reprise
./synscan -t 10.0.0.0/16 -p 1-1000 --resume 17b5c7a2e6e8f5520000b128
```

Les flags `--target` et `--ports` doivent etre identiques lors de la reprise.

## Integration NATS

- **Topic** : `scan.port.open`
- **Message** : `{"scan_id":"uuid","ip":"x.x.x.x","port":80,"timestamp":1707123456}`
- **Optionnel** : le scan fonctionne sans NATS (warning si connexion echouee)
- **Auth** : token ou user/password

### Pipeline complet

```
SynScan → scan.port.open → Grabber (fingerprint) → scan.port.fingerprinted → Grabber (enrichment) → scan.port.enriched → Datastore
```

```bash
# 1. Datastore (lance NATS embarque)
cd datastore && ./datastore -nats-token="SECRET" -verbose

# 2. Fingerprint
cd grabber && ./grab finger -c config.yaml

# 3. Enrichment
cd grabber && ./grab enrich -c config.yaml

# 4. Scan
cd synscan && ./synscan -t 192.168.1.0/24 -p 1-1000 --nats-url nats://localhost:4222 --nats-token SECRET
```

## Performances

Recommandations selon le contexte :

| Contexte | Rate limit | Notes |
|----------|------------|-------|
| LAN rapide | 5000-10000 PPS | Reseau local fiable |
| Internet | 1000-2000 PPS | Defaut raisonnable |
| Furtif | 100-500 PPS | Minimise la detection |

```bash
# Scan performant sur LAN
./synscan -t 10.0.0.0/24 -p 1-1000 -r 10000

# Scan prudent sur Internet
./synscan -t 203.0.113.0/24 -p 80,443,22 -r 500
```

## Sortie

Les ports ouverts sont affiches sur **stdout** (un par ligne, format `ip:port`) :

```
192.168.1.1:80
192.168.1.1:443
192.168.1.5:22
```

En mode verbose (`-v`), les ports fermes et filtres sont affiches sur **stderr** :

```
[-] 192.168.1.1:23 CLOSED
[?] 192.168.1.1:25 FILTERED
```

Un resume de configuration est affiche au debut du scan et un resume des resultats a la fin (sur stderr).

## Prerequis

- Go 1.24+
- Linux : root ou `CAP_NET_RAW` pour AF_PACKET / raw sockets
- Windows : Admin + Npcap pour les transports performants
- Sans privileges : fallback automatique sur TCP connect()

## Contraintes

- IPv4 uniquement (pas de support IPv6)
- Binaire statique, pas de CGO
