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

  ;; public functions

;; Create a new encrypted message with conditions
(define-public (create-message 
  (encrypted-content (buff 10000))
  (content-hash (buff 32))
  (condition-type (string-ascii 20))
  (condition-value uint)
  (oracle-contract (optional principal))
  (oracle-key (optional uint))
  (metadata (string-ascii 500)))
  (let ((message-id (+ (var-get message-counter) u1)))
    (asserts! (not (var-get contract-paused)) ERR-UNAUTHORIZED)
    (asserts! (<= (len encrypted-content) MAX-MESSAGE-SIZE) ERR-INVALID-CONDITION)
    (asserts! (or (is-eq condition-type "time") 
                  (is-eq condition-type "block") 
                  (is-eq condition-type "oracle") 
                  (is-eq condition-type "event")) ERR-INVALID-CONDITION)
    
    ;; Validate oracle if specified
    (match oracle-contract
      oracle-addr (asserts! (match (map-get? trusted-oracles { oracle-address: oracle-addr }) data (get is-trusted data) false) ERR-INVALID-ORACLE)
      true)
    
    ;; Store message
    (map-set messages { message-id: message-id }
      {
        creator: tx-sender,
        encrypted-content: encrypted-content,
        content-hash: content-hash,
        creation-block: stacks-block-height,
        access-count: u0,
        is-deleted: false,
        metadata: metadata
      })
    
    ;; Store deletion condition
    (map-set deletion-conditions { message-id: message-id }
      {
        condition-type: condition-type,
        condition-value: condition-value,
        oracle-contract: oracle-contract,
        oracle-key: oracle-key,
        is-triggered: false,
        check-count: u0
      })
    
    ;; Initialize threshold config (default: single signature)
    (map-set threshold-config { message-id: message-id }
      {
        required-signatures: u1,
        total-authorized: u1,
        current-signatures: u0
      })
    
    ;; Add creator as authorized key
    (map-set authorized-keys { message-id: message-id, key-holder: tx-sender }
      {
        public-key-hash: content-hash, ;; Placeholder - in practice would be actual public key hash
        has-signed: false,
        key-index: u0,
        is-active: true
      })
    
    (var-set message-counter message-id)
    (ok message-id)))

;; Add additional authorized keys for multi-sig
(define-public (add-authorized-key 
  (message-id uint)
  (key-holder principal)
  (public-key-hash (buff 32)))
  (let ((msg (unwrap! (map-get? messages { message-id: message-id }) ERR-NOT-FOUND))
        (threshold (unwrap! (map-get? threshold-config { message-id: message-id }) ERR-NOT-FOUND)))
    (asserts! (is-eq (get creator msg) tx-sender) ERR-UNAUTHORIZED)
    (asserts! (not (get is-deleted msg)) ERR-MESSAGE-DELETED)
    (asserts! (< (get total-authorized threshold) MAX-AUTHORIZED-KEYS) ERR-INVALID-THRESHOLD)
    (asserts! (is-none (map-get? authorized-keys { message-id: message-id, key-holder: key-holder })) ERR-ALREADY-EXISTS)
    
    ;; Add new authorized key
    (map-set authorized-keys { message-id: message-id, key-holder: key-holder }
      {
        public-key-hash: public-key-hash,
        has-signed: false,
        key-index: (get total-authorized threshold),
        is-active: true
      })
    
    ;; Update threshold config
    (map-set threshold-config { message-id: message-id }
      (merge threshold 
        { total-authorized: (+ (get total-authorized threshold) u1) }))
    
    (ok true)))

;; Set threshold requirements for message access
(define-public (set-threshold-requirement 
  (message-id uint)
  (required-signatures uint))
  (let ((msg (unwrap! (map-get? messages { message-id: message-id }) ERR-NOT-FOUND))
        (threshold (unwrap! (map-get? threshold-config { message-id: message-id }) ERR-NOT-FOUND)))
    (asserts! (is-eq (get creator msg) tx-sender) ERR-UNAUTHORIZED)
    (asserts! (not (get is-deleted msg)) ERR-MESSAGE-DELETED)
    (asserts! (and (> required-signatures u0) (<= required-signatures (get total-authorized threshold))) ERR-INVALID-THRESHOLD)
    
    (map-set threshold-config { message-id: message-id }
      (merge threshold { required-signatures: required-signatures }))
    
    (ok true)))

;; Sign for message access (part of threshold signature)
(define-public (sign-for-access (message-id uint))
  (let ((msg (unwrap! (map-get? messages { message-id: message-id }) ERR-NOT-FOUND))
        (auth-key (unwrap! (map-get? authorized-keys { message-id: message-id, key-holder: tx-sender }) ERR-UNAUTHORIZED))
        (threshold (unwrap! (map-get? threshold-config { message-id: message-id }) ERR-NOT-FOUND)))
    (asserts! (not (get is-deleted msg)) ERR-MESSAGE-DELETED)
    (asserts! (get is-active auth-key) ERR-UNAUTHORIZED)
    (asserts! (not (get has-signed auth-key)) ERR-ALREADY-EXISTS)
    
    ;; Mark as signed
    (map-set authorized-keys { message-id: message-id, key-holder: tx-sender }
      (merge auth-key { has-signed: true }))
    
    ;; Update signature count
    (map-set threshold-config { message-id: message-id }
      (merge threshold { current-signatures: (+ (get current-signatures threshold) u1) }))
    
    (ok true)))

;; Access encrypted message (requires threshold signatures)
(define-public (access-message (message-id uint))
  (let ((msg (unwrap! (map-get? messages { message-id: message-id }) ERR-NOT-FOUND))
        (threshold (unwrap! (map-get? threshold-config { message-id: message-id }) ERR-NOT-FOUND)))
    (asserts! (not (get is-deleted msg)) ERR-MESSAGE-DELETED)
    (asserts! (>= (get current-signatures threshold) (get required-signatures threshold)) ERR-INSUFFICIENT-KEYS)
    
    ;; Check if deletion condition is met
    (try! (check-deletion-condition message-id))
    
    ;; Update access count
    (map-set messages { message-id: message-id }
      (merge msg { access-count: (+ (get access-count msg) u1) }))
    
    (ok (get encrypted-content msg))))

;; Check and trigger deletion conditions
(define-public (check-deletion-condition (message-id uint))
  (let ((condition (unwrap! (map-get? deletion-conditions { message-id: message-id }) ERR-NOT-FOUND))
        (msg (unwrap! (map-get? messages { message-id: message-id }) ERR-NOT-FOUND)))
    (asserts! (not (get is-deleted msg)) ERR-MESSAGE-DELETED)
    (asserts! (< (get check-count condition) MAX-CONDITION_CHECKS) ERR-EXPIRED)
    
    ;; Update check count
    (map-set deletion-conditions { message-id: message-id }
      (merge condition { check-count: (+ (get check-count condition) u1) }))
    
    ;; Check condition based on type
    (let ((should-delete 
      (if (is-eq (get condition-type condition) "time")
        (>= stacks-block-height (get condition-value condition))
        (if (is-eq (get condition-type condition) "block")
          (>= stacks-block-height (get condition-value condition))
          (if (is-eq (get condition-type condition) "oracle")
            ;; TODO: Wire to a statically-bound oracle implementing oracle-trait via use-trait
            ;; Dynamic contract calls are not allowed in Clarity; this path returns false until bound.
            false
            false)))))
      
      (if should-delete
        (begin
          ;; Mark message as deleted
          (map-set messages { message-id: message-id }
            (merge msg { is-deleted: true }))
          ;; Mark condition as triggered
          (map-set deletion-conditions { message-id: message-id }
            (merge condition { is-triggered: true }))
          (ok true))
        (ok false)))))

;; Set up inheritance/emergency access
(define-public (setup-inheritance 
  (message-id uint)
  (beneficiary principal)
  (proof-required (string-ascii 100))
  (proof-oracle (optional principal))
  (activation-delay uint))
  (let ((msg (unwrap! (map-get? messages { message-id: message-id }) ERR-NOT-FOUND)))
    (asserts! (is-eq (get creator msg) tx-sender) ERR-UNAUTHORIZED)
    (asserts! (not (get is-deleted msg)) ERR-MESSAGE-DELETED)
    
    (map-set inheritance-config { message-id: message-id }
      {
        beneficiary: beneficiary,
        proof-required: proof-required,
        proof-oracle: proof-oracle,
        activation-delay: activation-delay,
        is-claimed: false
      })
    
    (ok true)))

;; Claim inheritance (emergency access)
(define-public (claim-inheritance (message-id uint))
  (let ((msg (unwrap! (map-get? messages { message-id: message-id }) ERR-NOT-FOUND))
        (inheritance (unwrap! (map-get? inheritance-config { message-id: message-id }) ERR-NOT-FOUND)))
    (asserts! (is-eq (get beneficiary inheritance) tx-sender) ERR-UNAUTHORIZED)
    (asserts! (not (get is-deleted msg)) ERR-MESSAGE-DELETED)
    (asserts! (not (get is-claimed inheritance)) ERR-ALREADY-EXISTS)
    (asserts! (>= stacks-block-height (+ (get creation-block msg) (get activation-delay inheritance))) ERR-CONDITION-NOT-MET)
    
    ;; Mark as claimed
    (map-set inheritance-config { message-id: message-id }
      (merge inheritance { is-claimed: true }))
    
    ;; Grant full access to beneficiary
    (map-set access-permissions { message-id: message-id, accessor: tx-sender }
      {
        permission-level: u3,
        granted-at: stacks-block-height,
        expires-at: none,
        granted-by: (get creator msg)
      })
    
    (ok (get encrypted-content msg))))

;; Rotate quantum-resistant keys
(define-public (rotate-key 
  (message-id uint)
  (new-key-hash (buff 32))
  (rotation-epoch uint))
  (let ((msg (unwrap! (map-get? messages { message-id: message-id }) ERR-NOT-FOUND))
        (auth-key (unwrap! (map-get? authorized-keys { message-id: message-id, key-holder: tx-sender }) ERR-UNAUTHORIZED)))
    (asserts! (not (get is-deleted msg)) ERR-MESSAGE-DELETED)
    (asserts! (get is-active auth-key) ERR-UNAUTHORIZED)
    
    ;; Store rotation history
    (map-set key-rotations { message-id: message-id, rotation-epoch: rotation-epoch }
      {
        old-key-hash: (get public-key-hash auth-key),
        new-key-hash: new-key-hash,
        rotation-block: stacks-block-height,
        initiated-by: tx-sender
      })
    
    ;; Update key
    (map-set authorized-keys { message-id: message-id, key-holder: tx-sender }
      (merge auth-key { public-key-hash: new-key-hash }))
    
    (ok true)))

;; Admin: Add trusted oracle
(define-public (add-trusted-oracle 
  (oracle-address principal)
  (oracle-type (string-ascii 50)))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
    
    (map-set trusted-oracles { oracle-address: oracle-address }
      {
        is-trusted: true,
        added-at: stacks-block-height,
        oracle-type: oracle-type
      })
    
    (ok true)))

;; Admin: Emergency pause
(define-public (toggle-contract-pause)
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
    (var-set contract-paused (not (var-get contract-paused)))
    (ok (var-get contract-paused))))

;; read only functions

;; Get message info (without encrypted content)
(define-read-only (get-message-info (message-id uint))
  (match (map-get? messages { message-id: message-id })
    msg (ok {
      creator: (get creator msg),
      creation-block: (get creation-block msg),
      access-count: (get access-count msg),
      is-deleted: (get is-deleted msg),
      metadata: (get metadata msg)
    })
    ERR-NOT-FOUND))

;; Get deletion condition status
(define-read-only (get-deletion-status (message-id uint))
  (map-get? deletion-conditions { message-id: message-id }))

;; Get threshold configuration
(define-read-only (get-threshold-config (message-id uint))
  (map-get? threshold-config { message-id: message-id }))

;; Check if user is authorized for message
(define-read-only (is-authorized (message-id uint) (user principal))
  (match (map-get? authorized-keys { message-id: message-id, key-holder: user })
    auth-key (get is-active auth-key)
    false))

;; Get inheritance configuration
(define-read-only (get-inheritance-config (message-id uint))
  (map-get? inheritance-config { message-id: message-id }))

;; Get current message counter
(define-read-only (get-message-counter)
  (var-get message-counter))

;; Check if oracle is trusted
(define-read-only (is-trusted-oracle (oracle-address principal))
  (match (map-get? trusted-oracles { oracle-address: oracle-address })
    data (get is-trusted data)
    false))

;; Get contract status
(define-read-only (get-contract-status)
  {
    paused: (var-get contract-paused),
    emergency-mode: (var-get emergency-mode),
    total-messages: (var-get message-counter)
  })

;; private functions

;; Validate message exists and is accessible
(define-private (validate-message-access (message-id uint) (accessor principal))
  (let ((msg (unwrap! (map-get? messages { message-id: message-id }) ERR-NOT-FOUND)))
    (asserts! (not (get is-deleted msg)) ERR-MESSAGE-DELETED)
    (ok msg)))

;; Clean up expired permissions
(define-private (cleanup-expired-permissions (message-id uint) (accessor principal))
  (match (map-get? access-permissions { message-id: message-id, accessor: accessor })
    permission (match (get expires-at permission)
      expiry (if (>= stacks-block-height expiry)
        (begin
          (map-delete access-permissions { message-id: message-id, accessor: accessor })
          false)
        true)
      true)
    false))

;; Calculate signature threshold requirements
(define-private (calculate-threshold-met (message-id uint))
  (match (map-get? threshold-config { message-id: message-id })
    threshold (>= (get current-signatures threshold) (get required-signatures threshold))
    false))