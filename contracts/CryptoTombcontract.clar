;; title: CryptoTomb - Quantum-Resistant Message Vault
;; version: 1.0.0
;; summary: A secure vault for storing encrypted messages with conditional auto-deletion
;; description: Store encrypted messages that automatically delete based on time, block height, 
;;              oracle events, or other conditions. Features quantum-resistant encryption,
;;              multi-key threshold decryption, and emergency inheritance mechanisms.

;; traits
(define-trait oracle-trait
  ((get-value (uint) (response uint uint))))

;; token definitions
;; No tokens needed for this contract

;; constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-UNAUTHORIZED (err u1000))
(define-constant ERR-NOT-FOUND (err u1001))
(define-constant ERR-ALREADY-EXISTS (err u1002))
(define-constant ERR-INVALID-CONDITION (err u1003))
(define-constant ERR-MESSAGE-DELETED (err u1004))
(define-constant ERR-CONDITION-NOT-MET (err u1005))
(define-constant ERR-INVALID-THRESHOLD (err u1006))
(define-constant ERR-INSUFFICIENT-KEYS (err u1007))
(define-constant ERR-EXPIRED (err u1008))
(define-constant ERR-INVALID-ORACLE (err u1009))

;; Maximum message size (in bytes)
(define-constant MAX-MESSAGE-SIZE u10000)
;; Maximum number of authorized keys per message
(define-constant MAX-AUTHORIZED-KEYS u10)
;; Maximum condition check attempts
(define-constant MAX-CONDITION_CHECKS u1000)

;; data vars
(define-data-var message-counter uint u0)
(define-data-var contract-paused bool false)
(define-data-var emergency-mode bool false)

;; data maps
;; Main message storage
(define-map messages
  { message-id: uint }
  {
    creator: principal,
    encrypted-content: (buff 10000),
    content-hash: (buff 32),
    creation-block: uint,
    access-count: uint,
    is-deleted: bool,
    metadata: (string-ascii 500)
  })

;; Deletion conditions for each message
(define-map deletion-conditions
  { message-id: uint }
  {
    condition-type: (string-ascii 20), ;; "time", "block", "oracle", "event"
    condition-value: uint,
    oracle-contract: (optional principal),
    oracle-key: (optional uint),
    is-triggered: bool,
    check-count: uint
  })

;; Multi-signature threshold requirements
(define-map threshold-config
  { message-id: uint }
  {
    required-signatures: uint,
    total-authorized: uint,
    current-signatures: uint
  })

;; Authorized keys for each message
(define-map authorized-keys
  { message-id: uint, key-holder: principal }
  {
    public-key-hash: (buff 32),
    has-signed: bool,
    key-index: uint,
    is-active: bool
  })

;; Emergency inheritance settings
(define-map inheritance-config
  { message-id: uint }
  {
    beneficiary: principal,
    proof-required: (string-ascii 100), ;; "death-certificate", "time-elapsed", etc.
    proof-oracle: (optional principal),
    activation-delay: uint,
    is-claimed: bool
  })

;; Access permissions and logs
(define-map access-permissions
  { message-id: uint, accessor: principal }
  {
    permission-level: uint, ;; 1=read, 2=decrypt, 3=admin
    granted-at: uint,
    expires-at: (optional uint),
    granted-by: principal
  })

;; Oracle whitelist for trusted data sources
(define-map trusted-oracles
  { oracle-address: principal }
  {
    is-trusted: bool,
    added-at: uint,
    oracle-type: (string-ascii 50)
  })

;; Key rotation tracking
(define-map key-rotations
  { message-id: uint, rotation-epoch: uint }
  {
    old-key-hash: (buff 32),
    new-key-hash: (buff 32),
    rotation-block: uint,
    initiated-by: principal
  })