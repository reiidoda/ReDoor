# UML Views

## 1. Component Diagram

```mermaid
flowchart LR
  subgraph Mobile["Mobile Client"]
    UI["SwiftUI"] --> VM["ChatViewModel"]
    VM --> RS["RedoorService"]
    RS --> FFI["RedoorFFI"]
    FFI --> CE["ClientEngine"]
  end

  CE --> RC["RelayClient"]
  CE --> DC["DirectoryClient"]
  CE --> BC["BlockchainClient"]

  RC --> RELAY["Relay Service"]
  DC --> DIRECTORY["Directory Service"]
  BC --> BLOCKCHAIN["Blockchain Service"]
```

## 2. Class Diagram (Conceptual)

```mermaid
classDiagram
  class ChatViewModel {
    +sendMessage(content)
    +connect()
    +lock()
  }

  class RedoorService {
    +sendMessage(peer, content)
    +pollMessages()
    +secureWipe()
  }

  class ClientEngine {
    +send_message(peer, payload)
    +poll_messages()
    +secure_wipe()
  }

  class RelayClient {
    +send(envelope)
    +fetch_pending(receiver)
  }

  class DirectoryClient {
    +resolve(username)
    +query_prekey(id)
  }

  class BlockchainClient {
    +submit_commitment(hash)
    +verify_chain()
  }

  ChatViewModel --> RedoorService
  RedoorService --> ClientEngine
  ClientEngine --> RelayClient
  ClientEngine --> DirectoryClient
  ClientEngine --> BlockchainClient
```

## 3. Deployment Diagram (Logical)

```mermaid
flowchart TB
  subgraph Device["iOS Device"]
    APP["RedoorApp"]
    RUNTIME["Rust Runtime (FFI)"]
    APP --> RUNTIME
  end

  subgraph Edge["Internet / Edge"]
    LB1["Relay Load Balancer"]
    LB2["Directory/API Gateway"]
    LB3["Evidence/API Gateway"]
  end

  subgraph Services["Service Cluster"]
    R1["Relay Node A"]
    R2["Relay Node B"]
    D1["Directory Node"]
    B1["Blockchain Node"]
  end

  APP --> LB1 --> R1
  LB1 --> R2
  APP --> LB2 --> D1
  APP --> LB3 --> B1
```

## 4. Sequence Diagram (Message Delivery)

```mermaid
sequenceDiagram
  participant AliceApp as Alice App
  participant Engine as ClientEngine
  participant Relay as Relay
  participant BobApp as Bob App

  AliceApp->>Engine: sendMessage("hello")
  Engine->>Engine: encrypt envelope
  Engine->>Relay: POST /relay
  Relay-->>Engine: 200 accepted
  BobApp->>Relay: GET /fetch_pending
  Relay-->>BobApp: blob_base64
  BobApp->>BobApp: decrypt in memory
```

## 5. State Diagram (Client Security State)

```mermaid
stateDiagram-v2
  [*] --> Locked
  Locked --> Active: unlock/auth
  Active --> Background: app resigns
  Background --> Locked: auto-lock policy
  Active --> Duress: duress trigger
  Duress --> Locked: secure wipe complete
  Locked --> [*]
```

