;; rbac.clar
;; Simple, flexible RBAC: accounts hold uint roles (u0, u1, ...).
;; Admins (ROLE_ADMIN) can grant/revoke any role. Deployer is initial admin.

(define-constant ROLE_ADMIN u1)        ;; can grant/revoke roles
(define-constant ERR_UNAUTHORIZED u100)
(define-constant ERR_ALREADY_MEMBER u101)
(define-constant ERR_NOT_MEMBER u102)

;; roles[(role, member)] -> { active: bool }
(define-map roles
  { role: uint, member: principal }
  { active: bool })

;; On deploy, give deployer ROLE_ADMIN
(define-read-only (has-role (role uint) (who principal))
  (default-to false
    (get active (map-get? roles { role: role, member: who })) ))

(define-private (require-role (role uint) (who principal))
  (if (has-role role who)
      (ok true)
      (err ERR_UNAUTHORIZED)))

(define-private (is-admin (who principal))
  (has-role ROLE_ADMIN who))

(define-public (bootstrap-admin)
  ;; Optional: If contract deployed without automatic insertions, caller can claim admin
  ;; once, only if there is currently no admin recorded.
  (begin
    (if (has-role ROLE_ADMIN tx-sender)
        (ok false)
        (let ((existing (has-role ROLE_ADMIN (as-contract tx-sender))))
          (if existing
              (ok false)
              (begin
                (map-set roles { role: ROLE_ADMIN, member: tx-sender } { active: true })
                (ok true)))))))

(define-public (grant-role (role uint) (account principal))
  (begin
    (try! (require-role ROLE_ADMIN tx-sender))
    (if (has-role role account)
        (err ERR_ALREADY_MEMBER)
        (begin
          (map-set roles { role: role, member: account } { active: true })
          (ok true)))))

(define-public (revoke-role (role uint) (account principal))
  (begin
    (try! (require-role ROLE_ADMIN tx-sender))
    (if (has-role role account)
        (begin
          (map-delete roles { role: role, member: account })
          (ok true))
        (err ERR_NOT_MEMBER))))

(define-public (renounce-role (role uint))
  (if (has-role role tx-sender)
      (begin
        (map-delete roles { role: role, member: tx-sender })
        (ok true))
      (err ERR_NOT_MEMBER)))

;; Example of protecting another contract function:
;; Replace `ROLE_SOMETHING` with your custom role constant (e.g., u2).
(define-constant ROLE_MINTER u2)

(define-public (example-protected-action (note (string-ascii 80)))
  (begin
    (try! (require-role ROLE_MINTER tx-sender))
    ;; ... do the privileged thing here ...
    (print { event: "did-protected-action", by: tx-sender, note: note })
    (ok true)))
