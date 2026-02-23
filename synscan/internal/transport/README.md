# Transport Layer Architecture

Le système de transport de synscan est modulaire et multi-plateforme. Il détecte automatiquement la meilleure méthode disponible selon la plateforme et les privilèges.

## Architecture

```
internal/transport/
├── transport.go              # Interface commune (cross-platform)
├── connect.go                # Mode Connect (cross-platform)
│
├── detector_linux.go         # Détection Linux
├── afpacket_linux.go         # AF_PACKET + mmap (Linux uniquement)
├── rawsocket_linux.go        # Raw sockets + sendmmsg (Linux)
│
├── detector_windows.go       # Détection Windows
└── rawsocket_windows.go      # Raw sockets Windows (limité)
```

## Méthodes de Transport

### Linux

#### 1. AF_PACKET + mmap (PACKET_TX_RING/RX_RING)
- **Performance**: ~2M PPS
- **Requis**: Root/CAP_NET_RAW + kernel 2.6.27+
- **Avantages**: Zero-copy I/O, latence minimale
- **Fichier**: `afpacket_linux.go`

#### 2. Raw Socket + sendmmsg/recvmmsg
- **Performance**: ~500K PPS
- **Requis**: Root/CAP_NET_RAW
- **Avantages**: Compatible 2.6.x anciens, batching efficace
- **Fichier**: `rawsocket_linux.go`

#### 3. Mode Connect()
- **Performance**: ~10K PPS
- **Requis**: Aucun privilège
- **Avantages**: Fonctionne partout
- **Fichier**: `connect.go`

### Windows

#### 1. Raw Socket (NON SUPPORTÉ)
- **Status**: Désactivé
- **Raison**: Windows XP SP2+ ne supporte pas IP_HDRINCL pour TCP
- **Fichier**: `rawsocket_windows.go`

#### 2. Mode Connect()
- **Performance**: ~10K PPS
- **Requis**: Aucun privilège
- **Avantages**: Seule méthode fiable sur Windows
- **Fichier**: `connect.go`

## Détection Automatique

Le système essaie les transports dans l'ordre de performance :

**Linux**:
```
AF_PACKET+mmap → Raw Socket → Connect
```

**Windows**:
```
Raw Socket (échec) → Connect
```

## Interface Transport

Chaque transport implémente l'interface :

```go
type Transport interface {
    Method() TransportMethod
    Send(packets []*Packet) (int, error)
    Receive(ctx context.Context) ([]*ReceivedPacket, error)
    Close() error
    GetCapabilities() Capabilities
}
```

## Capabilities

Chaque transport expose ses capacités :

```go
type Capabilities struct {
    SupportsSYNScan          bool  // Vrai SYN scan
    SupportsCustomSourcePort bool  // Port source personnalisé
    SupportsRawPackets       bool  // Forge de paquets
    RequiresRoot             bool  // Privilèges requis
    MaxPacketsPerSecond      int   // PPS estimé
}
```

## Build Tags

Go utilise automatiquement les suffixes de fichiers :
- `*_linux.go` → compilé uniquement sur Linux
- `*_windows.go` → compilé uniquement sur Windows
- `*.go` (sans suffixe) → cross-platform

Pas besoin de `// +build` tags explicites !

## Compilation Cross-Platform

```bash
# Linux
make build

# Windows (depuis Linux)
GOOS=windows GOARCH=amd64 go build -o synscan.exe ./cmd/synscan

# Binaire standalone (pas de dépendances)
CGO_ENABLED=0 go build -o synscan ./cmd/synscan
```

## Pourquoi pas WinPcap/Npcap ?

- **Dépendance externe**: Nécessite installation séparée
- **Complexité**: Bindings CGO, drivers
- **Portabilité**: Le binaire ne serait plus standalone

Le mode Connect est largement suffisant pour la plupart des cas d'usage sur Windows.

## Extensions Futures

Pour ajouter un nouveau transport :

1. Créer `newmethod_<platform>.go`
2. Implémenter l'interface `Transport`
3. Ajouter dans `detector_<platform>.go`
4. Aucune modification du scanner nécessaire !

## Limitations Windows

Les raw sockets Windows ne permettent **pas** :
- ❌ Forger l'en-tête IP (IP_HDRINCL)
- ❌ SYN scan stealthy
- ❌ Custom source port

Seul le mode Connect fonctionne (connexion TCP complète).
