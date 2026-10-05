(in-package #:cl-rfc8628/tests)

;;;; -- Refresh Grant Fixtures --

(defclass refresh-test-source (credential-source)
  ((credentials
    :initarg :credentials
    :initform nil
    :accessor refresh-test-source-credentials
    :documentation "The credentials currently published to this in-memory store.")
   (saves
    :initform 0
    :accessor refresh-test-source-saves
    :documentation "The number of publications to this store."))
  (:documentation "An in-memory primary source for refresh grant tests."))

(defmethod credential-source-load ((source refresh-test-source))
  (refresh-test-source-credentials source))

(defmethod credential-source-save ((source refresh-test-source) (credentials oauth-credentials))
  (incf (refresh-test-source-saves source))
  (setf (refresh-test-source-credentials source) credentials))

(defmethod credential-source-pathname ((source refresh-test-source))
  #P"/tmp/cl-rfc8628-tests/refresh.sexp")

(defmethod credential-source-label ((source refresh-test-source))
  "the refresh test store")

(defclass refresh-test-manager (refresh-grant-credential-manager)
  ((responses
    :initarg :responses
    :initform nil
    :accessor refresh-test-manager-responses
    :documentation "Queued (body status) replies or conditions, one per request.")
   (requests
    :initform nil
    :accessor refresh-test-manager-requests
    :documentation "The recorded requests, newest first, as property lists.")
   (content-type
    :initarg :content-type
    :initform *refresh-form-content-type*
    :reader refresh-test-manager-content-type
    :documentation "The request encoding this manager declares.")
   (lock-entries
    :initform 0
    :accessor refresh-test-manager-lock-entries
    :documentation "The number of times the refresh lock was taken.")
   (lock-action
    :initarg :lock-action
    :initform nil
    :reader refresh-test-manager-lock-action
    :documentation "An optional function run on acquiring the lock, before its body.")
   (locked-p
    :initform nil
    :accessor refresh-test-manager-locked-p
    :documentation "Whether the refresh lock is currently held."))
  (:documentation "A refresh grant manager with a scripted transport and observable lock."))

(defmethod credential-manager-provider-label ((manager refresh-test-manager))
  "Portal")

(defmethod credential-manager-login-hint ((manager refresh-test-manager))
  "log in to the portal")

(defmethod credential-manager-token-endpoint ((manager refresh-test-manager))
  "https://portal.example/oauth/token")

(defmethod credential-manager-client-id ((manager refresh-test-manager))
  "portal-client")

(defmethod credential-manager-refresh-content-type ((manager refresh-test-manager))
  (refresh-test-manager-content-type manager))

(defmethod credential-manager-refresh-request
    ((manager refresh-test-manager) &key url headers content)
  (push (list :url url :headers headers :content content
              :locked-p (refresh-test-manager-locked-p manager))
        (refresh-test-manager-requests manager))
  (let ((response (pop (refresh-test-manager-responses manager))))
    (if (typep response 'condition)
        (error response)
        (values (first response) (second response) nil))))

(defmethod credential-manager-call-with-refresh-lock
    ((manager refresh-test-manager) (function function))
  (incf (refresh-test-manager-lock-entries manager))
  (when (refresh-test-manager-lock-action manager)
    (funcall (refresh-test-manager-lock-action manager)))
  (setf (refresh-test-manager-locked-p manager) t)
  (unwind-protect (funcall function)
    (setf (refresh-test-manager-locked-p manager) nil)))

(defclass refresh-test-rotating-manager (refresh-test-manager)
  ()
  (:documentation "A manager whose single-use refresh tokens must rotate on every exchange."))

(defmethod credential-manager-validate-refresh-response
    ((manager refresh-test-rotating-manager) document (credentials oauth-credentials))
  (unless (and (stringp (json-get document "refresh_token"))
               (string/= (json-get document "refresh_token")
                         (oauth-credentials-refresh-token credentials)))
    (error *token-refresh-failed-class*
           :message "The portal refresh response did not rotate the refresh token.")))

(defmethod credential-manager-validate-credentials
    ((manager refresh-test-rotating-manager) (credentials oauth-credentials))
  (when (string= (oauth-credentials-access-token credentials) "unusable-access")
    (error *credentials-unavailable-class*
           :message "The stored portal credentials are unusable."
           :searched-paths nil))
  credentials)

(defun refresh-test--credentials (&key (access-token "old-access") (refresh-token "old-refresh")
                                       (account-id "user-1") id-token expires-at)
  "Return portal credentials stored in the refresh test source."
  (make-instance 'oauth-credentials
                 :access-token access-token :refresh-token refresh-token
                 :id-token id-token :account-id account-id :expires-at expires-at
                 :source-path #P"/tmp/cl-rfc8628-tests/refresh.sexp"))

(defun refresh-test--manager (&key (class 'refresh-test-manager) responses stored
                                   (content-type *refresh-form-content-type*) lock-action)
  "Return a CLASS manager with RESPONSES queued and STORED published."
  (make-instance class
                 :primary-source (make-instance 'refresh-test-source :credentials stored)
                 :responses responses :content-type content-type
                 :lock-action lock-action))

(defun refresh-test--body (&rest properties)
  "Return a JSON body holding PROPERTIES."
  (json-encode (apply #'json-object properties)))

(defun refresh-test--failure (thunk)
  "Return the refresh failure THUNK signals, or NIL."
  (handler-case (progn (funcall thunk) nil)
    (token-refresh-failed (condition) condition)))

(defun refresh-test--failure-text (thunk)
  "Return the report of the refresh failure THUNK signals, or NIL."
  (let ((condition (refresh-test--failure thunk)))
    (and condition (princ-to-string condition))))


;;;; -- Refresh Grant Tests --

(defun refresh-test--request-shape ()
  "Test the RFC 6749 request parameters, headers, and both encodings."
  (let* ((manager (refresh-test--manager
                   :responses (list (list (refresh-test--body "access_token" "new-access") 200))))
         (credentials (refresh-test--credentials)))
    (credential-manager-refresh-exchange manager credentials "old-refresh")
    (let* ((request (first (refresh-test-manager-requests manager)))
           (headers (getf request :headers)))
      (check (and (string= (getf request :url) "https://portal.example/oauth/token")
                  (equal (quri:url-decode-params (getf request :content))
                         '(("grant_type" . "refresh_token") ("refresh_token" . "old-refresh")
                           ("client_id" . "portal-client")))
                  (equal (cdr (assoc "Content-Type" headers :test #'string=))
                         *refresh-form-content-type*)
                  (equal (cdr (assoc "Accept" headers :test #'string=)) "application/json")
                  (assoc "User-Agent" headers :test #'string=))
             "a refresh form-encodes the grant and declares its media types")))
  (let ((manager (refresh-test--manager
                  :content-type *refresh-json-content-type*
                  :responses (list (list (refresh-test--body "access_token" "new-access") 200)))))
    (credential-manager-refresh-exchange manager (refresh-test--credentials) "old-refresh")
    (let ((document (json-decode (getf (first (refresh-test-manager-requests manager)) :content))))
      (check (and (string= (json-get document "grant_type") "refresh_token")
                  (string= (json-get document "refresh_token") "old-refresh")
                  (string= (json-get document "client_id") "portal-client"))
             "a JSON token endpoint receives the same grant as an object"))))

(defun refresh-test--responses ()
  "Test rotation, carried-over tokens, expiry, accounts, and malformed responses."
  (let* ((manager (refresh-test--manager))
         (previous (refresh-test--credentials :id-token "old-id")))
    (let ((rotated (credential-manager-refresh-response-credentials
                    manager previous
                    (refresh-test--body "access_token" "new-access" "refresh_token" "new-refresh"
                                        "expires_in" 900))))
      (check (and (string= (oauth-credentials-access-token rotated) "new-access")
                  (string= (oauth-credentials-refresh-token rotated) "new-refresh")
                  (string= (oauth-credentials-id-token rotated) "old-id")
                  (string= (oauth-credentials-account-id rotated) "user-1")
                  (<= 890 (- (oauth-credentials-expires-at rotated) (get-universal-time)) 910))
             "a response rotates tokens, keeps the OpenID token, and maps expires_in"))
    (let ((kept (credential-manager-refresh-response-credentials
                 manager previous
                 (refresh-test--body "access_token" (jwt (json-object "sub" "user-1" "exp" 4000000000))))))
      (check (and (string= (oauth-credentials-refresh-token kept) "old-refresh")
                  (= (oauth-credentials-expires-at kept) (unix-time->universal-time 4000000000)))
             "a response without rotation keeps the refresh token and reads the JWT expiry"))
    (dolist (case (list (list "not json" "malformed")
                        (list "[]" "malformed")
                        (list (refresh-test--body "refresh_token" "new") "omitted")
                        (list (refresh-test--body "access_token" "a" "id_token" "") "omitted")
                        (list (refresh-test--body "access_token" (jwt (json-object "sub" "user-2")))
                              "changed accounts")
                        (list (refresh-test--body "access_token" "a"
                                                  "id_token" (jwt (json-object "sub" "user-2")))
                              "changed accounts")))
      (destructuring-bind (body expected) case
        (let ((text (refresh-test--failure-text
                     (lambda ()
                       (credential-manager-refresh-response-credentials manager previous body)))))
          (check (and text (search "Portal" text) (search expected text))
                 "response ~S fails as ~A" body expected))))
    (check (refresh-test--failure
            (lambda ()
              (credential-manager-refresh-response-credentials
               (refresh-test--manager :class 'refresh-test-rotating-manager) previous
               (refresh-test--body "access_token" "a" "refresh_token" "old-refresh"))))
           "a manager's response validation rejects an unrotated single-use token")))

(defun refresh-test--rejections ()
  "Test rejected, failed, and invalid exchanges."
  (let* ((credentials (refresh-test--credentials :refresh-token "echoed-refresh"))
         (manager (refresh-test--manager
                   :stored credentials
                   :responses (list (list (refresh-test--body "error" "bad:echoed-refresh") 400))))
         (condition (refresh-test--failure
                     (lambda () (credential-manager-refresh-exchange manager credentials
                                                                     "echoed-refresh"))))
         (text (and condition (princ-to-string condition))))
    (check (and condition
                (= (token-refresh-failed-status condition) 400)
                (not (search "echoed-refresh" text))
                (not (search "echoed-refresh" (token-refresh-failed-response condition)))
                (search *refresh-redaction-marker* text)
                (search "Portal" text)
                (search "log in to the portal" text))
           "a rejection reports the redacted code, its status, and the login hint"))
  (let* ((credentials (refresh-test--credentials))
         (sibling (refresh-test--credentials :access-token "sibling-access"
                                             :refresh-token "sibling-refresh"))
         (manager (refresh-test--manager
                   :stored sibling
                   :responses (list (list (refresh-test--body "error" "refresh_token_reused") 400)))))
    (multiple-value-bind (adopted publish-p)
        (credential-manager-refresh-exchange manager credentials "old-refresh")
      (check (and (eq adopted sibling) (not publish-p))
             "a rejected token yields a sibling's published rotation unpublished")))
  (dolist (case (list (list (make-condition 'simple-error :format-control "socket"
                                                          :format-arguments nil)
                            "could not be completed")
                      (list (list nil 200) "invalid response")
                      (list (list "{}" nil) "invalid response")))
    (destructuring-bind (response expected) case
      (let ((text (refresh-test--failure-text
                   (lambda ()
                     (credential-manager-refresh-exchange
                      (refresh-test--manager :responses (list response))
                      (refresh-test--credentials) "old-refresh")))))
        (check (and text (search expected text))
               "a transport outcome ~S fails as ~A" response expected))))
  (let ((host-failure (make-condition 'token-refresh-failed :message "host deadline")))
    (check (eq (handler-case
                   (credential-manager-refresh-exchange
                    (refresh-test--manager :responses (list host-failure))
                    (refresh-test--credentials) "old-refresh")
                 (token-refresh-failed (condition) condition))
               host-failure)
           "a credential condition from the transport propagates intact")))

(defun refresh-test--locked-rotation ()
  "Test the refresh lock spans the reread, exchange, and publication."
  (let* ((stale (refresh-test--credentials :expires-at 0))
         (manager (refresh-test--manager
                   :stored stale
                   :responses (list (list (refresh-test--body "access_token" "new-access"
                                                              "refresh_token" "new-refresh")
                                          200))))
         (source (credential-manager-primary-source manager))
         (refreshed (credential-manager-refresh manager stale)))
    (check (and (string= (oauth-credentials-refresh-token refreshed) "new-refresh")
                (= (refresh-test-manager-lock-entries manager) 1)
                (getf (first (refresh-test-manager-requests manager)) :locked-p)
                (eq (refresh-test-source-credentials source) refreshed)
                (= (refresh-test-source-saves source) 1))
           "the leader exchanges and publishes while holding the refresh lock"))
  (let* ((stale (refresh-test--credentials :expires-at 0))
         (rotation (refresh-test--credentials :access-token "sibling-access"
                                              :refresh-token "sibling-refresh"
                                              :expires-at (+ (get-universal-time) 3600)))
         (manager nil))
    (setf manager (refresh-test--manager
                   :stored stale
                   :lock-action (lambda ()
                                  (setf (refresh-test-source-credentials
                                         (credential-manager-primary-source manager))
                                        rotation))))
    (check (and (eq (credential-manager-refresh manager stale) rotation)
                (null (refresh-test-manager-requests manager))
                (zerop (refresh-test-source-saves (credential-manager-primary-source manager))))
           "a rotation published while waiting for the lock is adopted unspent"))
  (let* ((stale (refresh-test--credentials :expires-at 0))
         (manager nil))
    (setf manager (refresh-test--manager
                   :class 'refresh-test-rotating-manager
                   :stored stale
                   :lock-action (lambda ()
                                  (setf (refresh-test-source-credentials
                                         (credential-manager-primary-source manager))
                                        (refresh-test--credentials
                                         :access-token "unusable-access"
                                         :refresh-token "sibling-refresh")))))
    (check (handler-case (progn (credential-manager-refresh manager stale) nil)
             (credentials-unavailable () t))
           "an adopted rotation passes the manager's credential validation"))
  (let ((manager (refresh-test--manager
                  :class 'refresh-test-rotating-manager
                  :stored (refresh-test--credentials :access-token "unusable-access"))))
    (check (handler-case (progn (credential-manager-load manager) nil)
             (credentials-unavailable () t))
           "loaded primary credentials pass the manager's credential validation")))

(defun run-refresh-tests ()
  "Run the RFC 6749 refresh grant tests."
  (refresh-test--request-shape)
  (refresh-test--responses)
  (refresh-test--rejections)
  (refresh-test--locked-rotation))
