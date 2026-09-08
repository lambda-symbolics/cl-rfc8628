(defpackage #:cl-rfc8628/tests
  (:use #:cl #:cl-rfc8628)
  (:export #:run-tests))

(in-package #:cl-rfc8628/tests)

(defvar *assertions* 0)

(defun check (value control &rest arguments)
  "Count one assertion and fail with CONTROL unless VALUE is true."
  (incf *assertions*)
  (unless value
    (error (apply #'format nil control arguments))))


;;;; -- Test Store --

(defvar *saved-credentials* nil)

(defclass test-credential-source (credential-source)
  ((pathname
    :initarg :pathname
    :reader test-credential-source-pathname)))

(defmethod credential-source-pathname ((source test-credential-source))
  (test-credential-source-pathname source))

(defmethod credential-source-save
    ((source test-credential-source) (credentials oauth-credentials))
  (setf *saved-credentials* credentials))

(defmethod credential-source-load ((source test-credential-source))
  *saved-credentials*)

(defmethod credential-source-label ((source test-credential-source))
  "the test credential source")

(defclass test-credential-manager (credential-manager)
  ((source
    :initarg :source
    :reader test-credential-manager-source)))

(defmethod credential-manager-primary-source ((manager test-credential-manager))
  (test-credential-manager-source manager))

(defun test-manager ()
  (make-instance
   'test-credential-manager
   :source (make-instance
            'test-credential-source
            :pathname #P"/tmp/cl-rfc8628-tests/auth.sexp")))


;;;; -- Wire Helpers --

(defun base64url (source)
  (string-right-trim
   "."
   (cl-base64:string-to-base64-string source :uri t)))

(defun jwt (payload)
  "Return an unsigned JWT carrying PAYLOAD claims."
  (format nil "~A.~A.~A"
          (base64url (json-encode (json-object "alg" "none")))
          (base64url (json-encode payload))
          (base64url "signature")))

(defun url-suffix-p (url suffix)
  (let ((mismatch (mismatch suffix url :from-end t)))
    (or (null mismatch) (zerop mismatch))))

(defun request-named (requests suffix)
  (find-if (lambda (request)
             (url-suffix-p (getf request :url) suffix))
           requests))

(defun token-response (&key (subject "user-1"))
  (json-encode
   (json-object
    "access_token" (jwt (json-object "sub" subject))
    "refresh_token" "refresh-test"
    "expires_in" 900
    "id_token" (jwt (json-object "sub" subject)))))

(defun request-code-response (&key (user-code "USER-CODE"))
  (json-encode
   (json-object
    "device_code" "device-code-1"
    "user_code" user-code
    "verification_uri" "https://issuer.test/activate"
    "verification_uri_complete"
    (format nil "https://issuer.test/activate?user_code=~A" user-code)
    "expires_in" 600
    "interval" 2)))

(defun client-create (&key request-function
                           (sleep-function #'identity)
                           (clock-function (constantly 0))
                           (browser-function (constantly t)))
  (make-instance
   'rfc8628-device-authentication-client
   :issuer "https://issuer.test"
   :client-id "test-client"
   :device-code-path "/oauth2/device/code"
   :token-path "/oauth2/token"
   :scope "openid offline_access"
   :request-function request-function
   :poll-function #'rfc8628-device-authentication-poll-for-tokens
   :sleep-function sleep-function
   :clock-function clock-function
   :browser-function browser-function))

(defun expect-failure (thunk stage &key status code)
  "Require THUNK to fail at STAGE with optional STATUS and CODE."
  (handler-case
      (progn
        (funcall thunk)
        (check nil "expected a device authentication failure at ~S" stage))
    (device-authentication-error (condition)
      (check (eq (device-authentication-error-stage condition) stage)
             "failure stage ~S is not ~S"
             (device-authentication-error-stage condition) stage)
      (when status
        (check (eql (device-authentication-error-status condition) status)
               "failure status is not ~S" status))
      (when code
        (check (equal (device-authentication-error-code condition) code)
               "failure code is not ~S" code)))))


;;;; -- Complete Flow --

(defun test-complete-flow ()
  "Exercise request, pending and slow_down polls, and secure publication."
  (let ((requests nil)
        (poll-count 0)
        (clock 0)
        (sleeps nil)
        (opened-url nil)
        (*saved-credentials* nil))
    (flet ((request (&key method url headers content)
             (push (list :method method :url url
                         :headers headers :content content)
                   requests)
             (cond
               ((url-suffix-p url "/oauth2/device/code")
                (values (request-code-response) 200 nil))
               ((url-suffix-p url "/oauth2/token")
                (incf poll-count)
                (case poll-count
                  (1 (values (json-encode
                              (json-object "error" "authorization_pending"))
                             400 nil))
                  (2 (values (json-encode (json-object "error" "slow_down"))
                             400 nil))
                  (t (values (token-response) 200 nil))))
               (t
                (error "Unexpected test URL."))))
           (pause (seconds)
             (push seconds sleeps)
             (incf clock seconds)))
      (let* ((client (client-create
                      :request-function #'request
                      :sleep-function #'pause
                      :clock-function (lambda () clock)
                      :browser-function (lambda (url)
                                          (setf opened-url url)
                                          t)))
             (output (make-string-output-stream))
             (result (device-authentication-login client (test-manager)
                                                  :stream output)))
        (check (eq result t) "the device login reports success")
        (let ((credentials *saved-credentials*))
          (check (and credentials
                      (string= (oauth-credentials-account-id credentials)
                               "user-1"))
                 "the published credentials carry the token subject")
          (check (string= (oauth-credentials-refresh-token credentials)
                          "refresh-test")
                 "the published credentials are renewable")
          (check (let ((expires-at
                         (oauth-credentials-expires-at credentials)))
                   (and expires-at
                        (<= 890 (- expires-at (get-universal-time)) 910)))
                 "expires_in maps to a credential expiration"))
        (let ((displayed (get-output-stream-string output)))
          (check (search "USER-CODE" displayed)
                 "the user code is displayed for confirmation")
          (check (search "https://issuer.test/activate?user_code=USER-CODE"
                         displayed)
                 "the complete verification URL is displayed")
          (check (not (search "device-code-1" displayed))
                 "the secret device code is never displayed"))
        (check (string= opened-url
                        "https://issuer.test/activate?user_code=USER-CODE")
               "the browser opens the complete verification URL")
        (check (= poll-count 3)
               "polling continues through pending and slow_down responses")
        (check (equal (reverse sleeps) '(2 2 7))
               "a slow_down response widens the polling interval")
        (let ((code-request (request-named requests "/oauth2/device/code")))
          (check (and code-request
                      (search "client_id=" (getf code-request :content))
                      (search "scope=" (getf code-request :content)))
                 "the device code request carries the client and scopes"))
        (let ((token-request (request-named requests "/oauth2/token")))
          (check (and token-request
                      (search "device_code=device-code-1"
                              (getf token-request :content))
                      (search "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
                              (getf token-request :content)))
                 "the token poll carries the RFC 8628 grant and device code"))))))


;;;; -- Rejections --

(defun test-rejections ()
  "Test denial, expiry, timeout, and malformed server responses."
  (labels ((client-for (responder)
             (let ((clock 0))
               (client-create
                :request-function responder
                :sleep-function (lambda (seconds) (incf clock seconds))
                :clock-function (lambda () clock))))
           (poll-responder (body status)
             (lambda (&key method url headers content)
               (declare (ignore method headers content))
               (if (url-suffix-p url "/oauth2/device/code")
                   (values (request-code-response) 200 nil)
                   (values body status nil))))
           (login (responder)
             (device-authentication-login
              (client-for responder)
              (test-manager)
              :stream (make-string-output-stream)
              :open-browser-p nil)))
    (expect-failure
     (lambda ()
       (login (poll-responder
               (json-encode (json-object "error" "access_denied")) 400)))
     ':poll :status 400 :code "access_denied")
    (expect-failure
     (lambda ()
       (login (poll-responder
               (json-encode (json-object "error" "expired_token")) 400)))
     ':poll :status 400 :code "expired_token")
    (expect-failure
     (lambda () (login (poll-responder "not-json" 200)))
     ':poll)
    (expect-failure
     (lambda ()
       (login (poll-responder
               (json-encode (json-object "access_token" "only-access")) 200)))
     ':credentials)
    (let ((*saved-credentials* nil))
      (expect-failure
       (lambda ()
         (login (poll-responder
                 (json-encode (json-object "error" "authorization_pending"))
                 400)))
       ':poll)
      (check (null *saved-credentials*)
             "an endless pending authorization publishes no credentials"))))


;;;; -- Request Code Validation --

(defun test-request-code-validation ()
  "Test rejection of malformed device authorization responses."
  (flet ((request-code (body)
           (device-authentication-request-code
            (client-create
             :request-function
             (lambda (&key method url headers content)
               (declare (ignore method url headers content))
               (values body 200 nil))))))
    (expect-failure
     (lambda ()
       (request-code (json-encode (json-object "user_code" "ONLY-CODE"))))
     ':request-code)
    (expect-failure
     (lambda ()
       (request-code
        (json-encode
         (json-object
          "device_code" "device-code-1"
          "user_code" (format nil "EVIL~CCODE" #\Newline)
          "verification_uri" "https://issuer.test/activate"
          "expires_in" 600))))
     ':request-code)
    (expect-failure
     (lambda ()
       (request-code
        (json-encode
         (json-object
          "device_code" "device-code-1"
          "user_code" "USER-CODE"
          "verification_uri" "javascript:alert(1)"
          "expires_in" 600))))
     ':request-code)))


;;;; -- Support --

(defun test-support ()
  "Test JWT claims, redaction, and error code extraction."
  (check (string= (jwt-subject (jwt (json-object "sub" "subject-1")))
                  "subject-1")
         "jwt-subject reads the unverified subject claim")
  (check (null (jwt-subject "not-a-jwt"))
         "jwt-subject tolerates malformed tokens")
  (check (integerp (jwt-expiration (jwt (json-object "exp" 1000))))
         "jwt-expiration converts Unix expirations")
  (check (string= (oauth-error-code
                   (json-encode (json-object "error" "slow_down")))
                  "slow_down")
         "oauth-error-code reads plain error strings")
  (check (string= (redact-exact-string-values
                   "code secret-1 tail" '("secret-1") "[X]")
                  "code [X] tail")
         "exact redaction replaces whole secrets")
  (let ((marker (safe-redaction-marker "[MARKER]" '("MARK"))))
    (check (not (search "MARK" marker))
           "the redaction marker never contains a secret")))


;;;; -- Entry --

(defun run-tests ()
  "Run the cl-rfc8628 tests and return true on success."
  (setf *assertions* 0)
  (test-support)
  (test-complete-flow)
  (test-rejections)
  (test-request-code-validation)
  (cl-rfc8628::run-manager-tests)
  (format t "~&~D cl-rfc8628 assertions passed.~%" *assertions*)
  t)
