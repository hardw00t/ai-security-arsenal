# Mermaid DFD Templates

Ready-to-adapt Mermaid templates for DFDs with trust boundaries. Frontier models render these inline in most chat surfaces.

## Template 1: Level-0 Context Diagram

```mermaid
flowchart LR
    User([End User])
    Admin([Admin])
    ThirdParty([3rd-Party API])

    subgraph system["System Under Analysis"]
        App([Application])
    end

    Store[(Data Store)]

    User -- "HTTPS / session cookie / PII" --> App
    Admin -- "HTTPS+MFA / admin token" --> App
    App -- "TLS / app creds / PII" --> Store
    App -- "HTTPS / OAuth2" --> ThirdParty
```

## Template 2: Classic 3-Tier Web App (Level-1)

```mermaid
flowchart TB
    subgraph internet[Internet - Untrusted]
        User([User Browser])
    end

    subgraph dmz["DMZ - TB1"]
        WAF([WAF])
        LB([Load Balancer])
    end

    subgraph apptier["Application Tier - TB2"]
        Web([Web Frontend])
        API([API Server])
        Worker([Async Worker])
    end

    subgraph datatier["Data Tier - TB3"]
        DB[(PostgreSQL)]
        Cache[(Redis)]
        Queue[(RabbitMQ)]
        Blob[(S3)]
    end

    subgraph external[Partner Trust Zone]
        Stripe([Stripe])
        Email([SES])
    end

    User -->|HTTPS| WAF
    WAF --> LB
    LB -->|HTTPS| Web
    Web -->|HTTPS+JWT| API
    API -->|TLS+creds| DB
    API -->|TLS| Cache
    API -->|AMQPS| Queue
    API -->|HTTPS+SigV4| Blob
    Queue --> Worker
    Worker -->|TLS+creds| DB
    Worker -->|HTTPS+OAuth2| Stripe
    Worker -->|HTTPS+SigV4| Email
```

## Template 3: Microservices with Service Mesh

```mermaid
flowchart TB
    subgraph edge[Edge]
        Gateway([API Gateway])
    end

    subgraph mesh["Service Mesh - mTLS between all"]
        Auth([auth-svc])
        Users([users-svc])
        Orders([orders-svc])
        Payments([payments-svc])
        Notifier([notifier-svc])
    end

    subgraph data[Data Tier]
        AuthDB[(auth-db)]
        UsersDB[(users-db)]
        OrdersDB[(orders-db)]
        Bus[(Kafka)]
    end

    Client([Client]) -->|HTTPS+JWT| Gateway
    Gateway -->|mTLS| Auth
    Gateway -->|mTLS| Users
    Gateway -->|mTLS| Orders
    Auth -->|TLS| AuthDB
    Users -->|TLS| UsersDB
    Orders -->|TLS| OrdersDB
    Orders -->|mTLS| Payments
    Orders -->|TLS+SASL_SSL| Bus
    Bus --> Notifier
```

## Template 4: Mobile App + Backend

```mermaid
flowchart LR
    subgraph device["Mobile Device - Untrusted"]
        App([Mobile App])
        Keychain[(Keychain/Keystore)]
    end

    subgraph edge["Backend Edge - TB1"]
        Gateway([API Gateway])
    end

    subgraph backend["Backend - TB2"]
        Auth([Auth Service])
        API([API])
    end

    DB[(Primary DB)]

    App -->|HTTPS + Cert Pinning + OAuth2| Gateway
    App <-->|secure enclave| Keychain
    Gateway -->|mTLS| Auth
    Gateway -->|mTLS| API
    Auth -->|TLS| DB
    API -->|TLS| DB
```

## Template 5: IoT / Edge

```mermaid
flowchart LR
    subgraph field[Field - Physically Untrusted]
        Device([IoT Device])
        GW([Edge Gateway])
    end

    subgraph cloud[Cloud Backend]
        Ingest([Ingest Service])
        Stream([Stream Processor])
        TS[(Time-Series DB)]
    end

    Device -->|MQTT+TLS+device cert| GW
    GW -->|AMQPS+mTLS| Ingest
    Ingest --> Stream
    Stream --> TS
```

## Template 6: AI/ML Inference Pipeline

```mermaid
flowchart LR
    User([User]) -->|HTTPS+JWT| API([API])
    API -->|TLS| Orchestrator([Orchestrator])
    Orchestrator -->|HTTPS+API key| LLM([External LLM Provider])
    Orchestrator -->|TLS| VectorDB[(Vector Store)]
    Orchestrator -->|TLS| Cache[(Prompt Cache)]
    Orchestrator --> Logger[(Audit Log - append-only)]

    subgraph trust["Untrusted Inputs"]
        UserInput([User Prompts])
        Docs([Retrieved Docs])
    end

    UserInput -.-> API
    Docs -.-> Orchestrator
```

## Styling Tips

Add colour to highlight trust zones:

```mermaid
flowchart LR
    classDef untrusted fill:#fee,stroke:#c33
    classDef trusted fill:#efe,stroke:#3c3
    classDef external fill:#fef,stroke:#93c

    User([User]):::untrusted
    App([App]):::trusted
    Stripe([Stripe]):::external
    User --> App --> Stripe
```

## Conventions in These Templates

- **Rectangles** = external entities (`User`, `Admin`)
- **Rounded rectangles / stadiums** (`([Name])`) = processes
- **Cylinders** (`[(Name)]`) = data stores
- **Subgraphs** = trust boundaries — name them `"<Zone Name> - TB<N>"`
- **Edge labels** = `protocol / auth / data classification`
