# Arhitectura Criptografică și Diagramarea Sistemului SecureP2PChat

Acest document conține specificația tehnică completă a sistemului **SecureP2PChat** (interoperabilitate Android Kotlin și Windows Python), documentată exclusiv prin **diagrame Mermaid** și explicații criptografice precise.

---

## 1. Arhitectura Rețelei și Relația Client - Server Releu

 Această diagramă descrie arhitectura de rețea, filtrarea prin Tor v3 / TLS 1.3 și comunicarea asincronă cu serverul de semnalizare.

```mermaid
flowchart LR
    subgraph ClientAndroid ["Client Android (Kotlin)"]
        A1["Identitate X25519 & Ed25519"]
        A2["Stocare Locală Criptată Argon2id"]
    end

    subgraph ClientDesktop ["Client Windows (Python)"]
        D1["Identitate X25519 & Ed25519"]
        D2["Stocare Locală Criptată SQLite/Vault"]
    end

    subgraph ReteaAnonymizata ["Transport Securizat & Anonim"]
        Tor1["Tunel Tor v3 Onion Service"]
        TLS1["Criptare TLS 1.3"]
    end

    subgraph ServerRelay ["Server de Semnalizare & Releu"]
        S1["Comenzi JSON Lines cu Semnături Ed25519"]
        S2["Cozi Temporare Ephemere (Poll / Ack)"]
    end

    ClientAndroid <--> ReteaAnonymizata
    ClientDesktop <--> ReteaAnonymizata
    ReteaAnonymizata <--> ServerRelay
    ServerRelay --> S2
    S2 --> ClientAndroid
    S2 --> ClientDesktop
```

---

## 2. Arborele Criptografic de Derivare a Cheilor 1:1 (Key Generation Tree)

 Diagrama de derivare ierarhică a cheilor de la parola utilizatorului până la cheile unice de mesaj 1:1 per sesiune.

```mermaid
flowchart TD
    Password["Parolă Utilizator + Salt Random (16 bytes)"] --> Argon2["Argon2id (t=3, m=64MB, p=4)"]
    Argon2 --> MasterKey["Master Key (32 bytes) - Criptează starea locală"]

    MasterKey --> X25519Keys["X25519 Keypair (PrivKey 32B, PubKey 32B)"]
    MasterKey --> Ed25519Keys["Ed25519 Keypair (PrivKey 32B, VerifyKey 32B)"]

    X25519Keys --> ECDHAgreement["Acord de Cheie ECDH X25519"]
    ECDHAgreement --> SessionKey["Session Key (32 bytes) via HKDF-SHA256"]

    SessionKey --> SendChainKey["Send Chain Key (FS2 1:1)"]
    SessionKey --> RecvChainKey["Receive Chain Key (FS2 1:1)"]

    SendChainKey --> SendNextChain["Send Chain Key (n + 1)"]
    SendChainKey --> SendMsgKey["Message Key n (32B) - Criptează SPC2-AEAD"]

    RecvChainKey --> RecvNextChain["Receive Chain Key (n + 1)"]
    RecvChainKey --> RecvMsgKey["Message Key n (32B) - Decriptează SPC2-AEAD"]

    SendMsgKey --> ZeroSendKey["Zeroizare Memorie RAM: fill(0)"]
    RecvMsgKey --> ZeroRecvKey["Zeroizare Memorie RAM: fill(0)"]
```

---

## 3. Arborele Criptografic al Cheilor de Grup (TreeKEM / MLS & GSK1 Tree)

 Această diagramă arată structura arborelui de chei de grup (Logarithmic TreeKEM / RFC 9420) și derivarea lanțurilor de mesaje per expeditor (GSK1):

```mermaid
flowchart TD
    subgraph TreeKEMTree ["Arborele Logaritmic de Grup TreeKEM O(log N)"]
        RootNode["Root Node (Rădăcina Arborelui)"]
        Node10["Parent Node (Level 1, Index 0)"]
        Node11["Parent Node (Level 1, Index 1)"]
        
        Leaf0["Leaf 0: Member A (Keypair A)"]
        Leaf1["Leaf 1: Member B (Keypair B)"]
        Leaf2["Leaf 2: Member C (Keypair C)"]
        Leaf3["Leaf 3: Member D (Keypair D)"]

        Leaf0 --> Node10
        Leaf1 --> Node10
        Leaf2 --> Node11
        Leaf3 --> Node11

        Node10 --> RootNode
        Node11 --> RootNode
    end

    subgraph EpochDerivation ["Derivare Secret de Epocă & Lanțuri GSK1"]
        RootNode -->|HKDF-SHA256| EpochSecret["Epoch Secret (32 bytes - Epoca E)"]
        
        EpochSecret -->|HKDF-SHA256| GSKA["GSK1 Chain (Sender A)"]
        EpochSecret -->|HKDF-SHA256| GSKB["GSK1 Chain (Sender B)"]
        EpochSecret -->|HKDF-SHA256| GSKC["GSK1 Chain (Sender C)"]
        EpochSecret -->|HKDF-SHA256| GSKD["GSK1 Chain (Sender D)"]

        GSKA --> MsgKeyA["Message Key A (32B fill(0))"]
        GSKB --> MsgKeyB["Message Key B (32B fill(0))"]
        GSKC --> MsgKeyC["Message Key C (32B fill(0))"]
        GSKD --> MsgKeyD["Message Key D (32B fill(0))"]
    end
```

---

## 4. Stabilirea Identității și a Cheilor 1:1 (Handshake HELLO)

 Secvența de conectare, autentificare prin semnătură digitală Ed25519 și derivare a cheii de sesiune 1:1.

```mermaid
sequenceDiagram
    autonumber
    participant ClientA as Expeditor (Client A)
    participant Relay as Server Releu (.onion)
    participant ClientB as Destinatar (Client B)

    ClientA->>Relay: register (device_id, verify_key, public_key, signature)
    ClientB->>Relay: register (device_id, verify_key, public_key, signature)
    ClientA->>Relay: relay_send (MSG_HELLO semnat Ed25519 + PubKey X25519)
    Relay->>ClientB: relay_poll livrează MSG_HELLO
    Note over ClientB: Verifică semnătura Ed25519 și fingerprint-ul
    Note over ClientB: Derivă SessionKey = X25519(priv_B, pub_A) + HKDF-SHA256
    ClientB->>Relay: relay_send (MSG_HELLO_ACK semnat Ed25519)
    Relay->>ClientA: relay_poll livrează MSG_HELLO_ACK
    Note over ClientA: Verifică semnătura Ed25519
    Note over ClientA: Derivă aceeași SessionKey = X25519(priv_A, pub_B) + HKDF-SHA256
    Note over ClientA,ClientB: Canalul securizat 1:1 (FS2) este activat!
```

---

## 5. Criptarea și Încapsularea Datelor (Transport & E2EE)

 Diagrama etapelor prin care trece un mesaj înainte de a fi transmis prin rețea.

```mermaid
flowchart TD
    PlaintextData["Date Brute (Text / Imagine / Audio / Fișier)"] --> JSONStructure["Structură JSON / Binară"]
    JSONStructure --> AEADEncryption["Criptare ChaCha20-Poly1305 (Envelope SPC2 v2)"]
    AEADEncryption --> FS2FrameHeader["Adăugare Antet FS2 ('FS2' + SessionID 16B + Counter 4B)"]
    FS2FrameHeader --> AADBinding["Legare Context AAD (Header + SenderID + RecvID)"]
    AADBinding --> RelayCommand["Comandă Relay JSON semnată Ed25519"]
    RelayCommand --> TLS13["Tunnel TLS 1.3"]
    TLS13 --> TorV3["Circuit Anonim Tor v3 (3 Hops)"]
    TorV3 --> ServerSocket["Transmisie Socket către Server Releu"]
```

---

## 6. Fluxul de Alăturare a unui Membru Nou și Rotația Epocii de Grup

 Diagrama de secvență pentru cererea și distribuirea cheii de grup la alăturarea unui membru nou.

```mermaid
sequenceDiagram
    autonumber
    participant MemberNew as Membru Nou
    participant Relay as Server Releu
    participant Creator as Creator Grup
    participant Members as Membri Existenți

    MemberNew->>Relay: group_join(invite_code)
    Relay-->>MemberNew: Înscris OK! Returnează group_id, creator_id, lista membri
    MemberNew->>Relay: MSG_HELLO către Creator
    Relay-->>Creator: Livrare MSG_HELLO
    Creator->>Relay: MSG_HELLO_ACK
    Relay-->>MemberNew: Livrare MSG_HELLO_ACK (Canal 1:1 FS2 stabilit)
    MemberNew->>Relay: MSG_GROUP_META (key_request) criptat FS2 către Creator
    Relay-->>Creator: Livrare key_request
    Note over Creator: Actualizează lista membri. S-a schimbat componența: incrementare Epoch = Epoch + 1
    Note over Creator: Generează un nou EpochSecret de 32B
    loop Pentru fiecare membru autorizat
        Creator->>Relay: MSG_GROUP_META (epoch_key) criptat FS2 individual
        Relay-->>Members: Livrare epoch_key individuală
    end
    Relay-->>MemberNew: Livrare epoch_key către Noul Membru
    Note over MemberNew: Salvează EpochSecret și procesează mesajele GSK1 din buffer
```

---

## 7. Transferul de Fișiere, Poze și Înregistrări Audio (Voice) în 1:1 și Grup

 Transferul fișierelor și al înregistrărilor audio prin fragmentare în bucăți de 64 KiB.

```mermaid
sequenceDiagram
    autonumber
    participant Sender as Expeditor (Android / Desktop)
    participant Relay as Server Releu
    participant Receiver as Destinatar

    Note over Sender: Sparge fișierul/vocea în bucăți de 64 KiB
    Sender->>Relay: FILE_START (transfer_id, filename, fileSize, totalChunks)
    Relay-->>Receiver: Livrare FILE_START
    loop Pentru fiecare bucată i de la 0 la totalChunks - 1
        Sender->>Relay: FILE_CHUNK (transfer_id, chunkIndex = i, data Base64)
        Relay-->>Receiver: Livrare FILE_CHUNK
    end
    Sender->>Relay: FILE_END (transfer_id)
    Relay-->>Receiver: Livrare FILE_END
    Note over Receiver: Reasamblează bucățile și criptează fișierul în seiful local (Vault)
    Note over Receiver: Afișează imaginea / fișierul / playerul audio în interfață
```

---

## 8. Specificația Algoritmilor Criptografici Utilizați

| Componentă | Algoritm / Standard | Parametri / Detalii Tehnice |
| :--- | :--- | :--- |
| **Protecție Locală** | Argon2id | $t=3$ iterații, $m=65536 \text{ KB}$ ($64 \text{ MB}$), $p=4$ paralelism |
| **Schimb Chei 1:1** | X25519 (Curve25519) | ECDH de 256 biți |
| **Semnătură Digitală** | Ed25519 | Autentificarea comenzilor și pachetelor HELLO |
| **Ratchet 1:1 (FS2)** | Symmetric Chain Ratchet | HKDF-SHA256, fereastră de skip $\le 1024$ mesaje |
| **Arbore Grup** | TreeKEM (RFC 9420 / MLS) | Arbore logaritmic $O(\log N)$, direct path updates |
| **Ratchet Mesaje Grup**| Group Sender Key Chain | HKDF-SHA256 derivat per expeditor și epocă |
| **Criptare Simetrică** | XChaCha20-Poly1305 (SPC2) | Nonce 24B, Tag 128-bit, AAD context binding |
| **Zeroizare Memorie** | Memory Wipe (`fill(0)`) | Ștergere directă a cheilor unice din RAM |
