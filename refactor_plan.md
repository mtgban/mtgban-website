## **Are you sure we cant sell fish?**

- [**Mtgban-Website Refactoring Plan of Action**](#mtgban-website-refactoring-plan-of-action)
  - [New Directory Structure](#new-directory-structure)
  - [Functions](#functions)
  - [Structs](#structs)
  - [Vars \& Constants](#vars--constants)

- [**Services Breakdown**]
  - [Search Service](#1-search-service)
    - [Functions](#functions-1)
    - [Structs](#structs-1)
  - [Newspaper Service](#2-newspaper-service)
    - [Functions](#functions-2)
    - [Structs](#structs-2)
  - [Sleepers Service](#3-sleepers-service)
    - [Functions](#functions-3)
    - [Structs](#structs-3)
  - [Upload Service](#4-upload-service)
    - [Functions](#functions-4)
    - [Structs](#structs-4)
  - [Arbitrage Service](#5-arbitrage-service)
    - [Global](#global-functions)
    - [Arbit](#arbit-functions)
    - [Reverse](#reverse-functions)
      - [Arbitrage Structs](#arbitrage-structs)


### Directory Structure

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

### Functions - ***[Top](#are-you-sure-we-cant-sell-fish)*** 
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

### Structs - ***[Top](#are-you-sure-we-cant-sell-fish)***
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

### Vars & Constants - ***[Top](#are-you-sure-we-cant-sell-fish)***
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


# Services Overview

## 1. Search Service - ***[Top](#are-you-sure-we-cant-sell-fish)***

### Functions:
- Search
- parseSearchOptionsNG
- searchAndFilter
- searchParallelNG
- processSellersResults
- processVendorsResults
- shouldSkipCardNG
- shouldSkipStoreNG
- shouldSkipPriceNG
- shouldSkipEntryNG
- sortSets
- sortSetsAlphabetical
- sortSetsByRetail
- sortSetsByBuylist

### Structs:
- SearchConfig
- FilterElem
- FilterStoreElem
- FilterPriceElem
- FilterEntryElem
- SearchEntry

## 2. Newspaper Service - ***[Top](#are-you-sure-we-cant-sell-fish)***

### Functions:
- Newspaper
- getLastDBUpdate

### Structs:
- Heading
- NewspaperPage

## 3. Sleepers Service - ***[Top](#are-you-sure-we-cant-sell-fish)***

### Functions:
- Sleepers
- getBulks
- getReprints
- getTiers
- sleepersLayout

### Structs:
- Sleeper

## 4. Upload Service - ***[Top](#are-you-sure-we-cant-sell-fish)***

### Functions:
- Upload
- parseHeader
- parseRow
- loadHashes
- loadCollection
- loadSpreadsheet
- loadOldXls
- loadXlsx
- loadCsv
- mergeIdenticalEntries
- getPrice
- getQuantity
- UUID2CKCSV
- UUID2SCGCSV

### Structs:
- UploadEntry
- OptimizedUploadEntry

## 5. Arbitrage Service - ***[Top](#are-you-sure-we-cant-sell-fish)***

### Global Functions:
- Global
- scraperCompare

### Arbit Functions:
- Arbit
- scraperCompare

### Reverse Functions:
- Reverse
- scraperCompare

### Structs: 
- Arbitrage

## 8. Admin Service - ***[Top](#are-you-sure-we-cant-sell-fish)***

### Functions:
- Admin
- pullCode
- build
- uptime
- mem
- getDemoKey
- generateAPIKey
- RefreshTable

### Structs:
- AppConfig

## 9. Datastore Service - ***[Top](#are-you-sure-we-cant-sell-fish)***

### Functions:
- startup
- loadInventoryFromTable
- loadBuylistFromTable
- loadBQ
- updateScraper
- updateStaticData
- loadInfos
- loadDatastore
- loadSellerFromFile
- dumpSellerToFile
- loadVendorFromFile
- dumpVendorToFile
- prepareCKAPI
- API
- getLastSold
- TCGLastSoldAPI

### Arbitrage Structs:
- dbElement
- LoadSummary
- EditionEntry
- ReprintEntry
- Dataset
- scraperConfig