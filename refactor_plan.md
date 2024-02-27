## **Mtgban-Website Refactoring Plan of Action**


- [**Mtgban-Website Refactoring Plan of Action**](#mtgban-website-refactoring-plan-of-action)
  - [New Directory Structure](#new-directory-structure)
  - [Functions](#functions)
  - [Structs](#structs)
  - [Vars \& Constants](#vars--constants)

### New Directory Structure
```sh
mtgban-website/
│
├── cmd/
│ └── main/ # Main application entry point
│      └── main.go # Initializes and starts the server
├── pkg/
│ ├── navigation/ # Functions and structs related to navigation
│ │     └── nav.go
| |         *vars* 
| |            - DefaultNav
| |            - ExtraNavs
| |            - OrderNav
| |
│ ├── database/ # Database operations
│ │     └── db.go
| |           *functions* 
| |               - openDBs
| |           *vars* 
| |              - DatabaseLoaded
│ │
│ ├── credentials/ # Managing credentials
│ │     └── loadGoogleCredentials.go # loadGoogleCredentials function
│ │
│ ├── handlers/ # HTTP handlers
│ │     ├── home.go # Home function
│ │     ├── search.go # Search function
│ │     ├── newspaper.go # Newspaper function
│ │     ├── sleepers.go # Sleepers function
│ │     ├── upload.go # Upload function
│ │     ├── global.go # Global function
│ │     ├── arbit.go # Arbit function
│ │     ├── reverse.go # Reverse function
│ │     ├── admin.go # Admin function
│ │     ├── auth.go # Auth function
│ │     ├── redirect.go # Redirect function
│ │     ├── randomSearch.go # RandomSearch function
│ │     └── randomSealedSearch.go # RandomSealedSearch function
│ │ 
│ │
│ ├── data/ # Data loading and processing
│ │     └── loadDatastore.go # loadDatastore function
│ │ 
│ │
│ ├── models/ # Data models
│ │     ├── pageVars.go # PageVars struct
│ │     └── navElem.go # NavElem struct
│ │ 
│ │
│ ├── config/ # Configuration-related structs and constants
│ │     ├── appConfig.go # AppConfig struct
│ │     └── constants.go # DefaultConfigPort, DefaultSecret, etc.
│ │
│ ├── logging/ # Logging operations
│ │     └── logPages.go # LogPages variable and related functions
│ │
│ ├── storage/ # Cloud storage operations
│ │     └── storage.go # Placeholder for storage-related functions
│ │
│ ├── credentials/ # Credentials loading and management
│ │     └── credentials.go # Placeholder for credentials-related functions
│ │
│ └── discord/ # Discord integration
│       ├── setupDiscord.go # setupDiscord function
│       └── cleanupDiscord.go # cleanupDiscord function
│
├── internal/ # Internal package
│   └── (internal packages)
│
└── README.md # Project documentation
```

### Functions 
| Functions             | Category    |
| --------------------- | ----------- |
| genPageNav            | navigation  |
| openDBs               | database    |
| loadGoogleCredentials | credentials |
| Home                  | handlers    |
| Search                | handlers    |
| Newspaper             | handlers    |
| Sleepers              | handlers    |
| Upload                | handlers    |
| Global                | handlers    |
| Arbit                 | handlers    |
| Reverse               | handlers    |
| Admin                 | handlers    |
| Auth                  | handlers    |
| Redirect              | handlers    |
| RandomSearch          | handlers    |
| RandomSealedSearch    | handlers    |
| TCGLastSoldAPI        | handlers    |
| CKMirrorAPI           | handlers    |
| PriceAPI              | handlers    |
| RefreshTable          | handlers    |
| API                   | handlers    |
| loadDatastore         | data        |
| startup               | data        |
| loadBQ                | data        |
| loadInfos             | data        |
| loadBQcron            | data        |
| setupDiscord          | discord     |
| cleanupDiscord        | discord     |

### Structs
| Struct               | Category |
| -------------------- | -------- |
| PageVars             | models   |
| NavElem              | models   |
| AppConfig            | config   |
| Dataset              | models   |
| Arbitrage            | models   |
| GenericCard          | models   |
| Heading              | models   |
| NewspaperPage        | models   |
| OptimizedUploadEntry | models   |
| SearchEntry          | models   |
| EditionEntry         | models   |
| ReprintEntry         | models   |

### Vars & Constants
| Name              | Category   |
| ----------------- | ---------- |
| startTime         | global     |
| DefaultNav        | navigation |
| ExtraNavs         | navigation |
| OrderNav          | navigation |
| LogPages          | logging    |
| Config            | config     |
| DevMode           | config     |
| SigCheck          | config     |
| BenchMode         | config     |
| FreeSignature     | config     |
| LogDir            | logging    |
| LastUpdate        | global     |
| DatabaseLoaded    | database   |
| Sellers           | data       |
| Vendors           | data       |
| Infos             | data       |
| DefaultConfigPort | config     |
| DefaultSecret     | config     |
| OptionalFields    | config     |
