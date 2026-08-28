(in-package #:cl-rfc8628)

;;;; -- OAuth Credentials --

(defclass oauth-credentials ()
  ((access-token
    :initarg :access-token
    :reader oauth-credentials-access-token
    :type non-empty-string
    :documentation "The bearer token used for one provider request scope.")
   (refresh-token
    :initarg :refresh-token
    :reader oauth-credentials-refresh-token
    :type (option string)
    :documentation "The rotating OAuth refresh token, if available.")
   (id-token
    :initarg :id-token
    :initform nil
    :reader oauth-credentials-id-token
    :type (option string)
    :documentation "The OpenID token, if supplied by the OAuth server.")
   (account-id
    :initarg :account-id
    :reader oauth-credentials-account-id
    :type non-empty-string
    :documentation "The stable account identity these credentials belong to.")
   (expires-at
    :initarg :expires-at
    :reader oauth-credentials-expires-at
    :type (option timestamp)
    :documentation "The access-token expiration in universal time, if known.")
   (source-path
    :initarg :source-path
    :reader oauth-credentials-source-path
    :type pathname
    :documentation "The file from which these request-scoped credentials came."))
  (:documentation "OAuth material held only inside request scope."))

(defun oauth-credentials-secret-values (credentials)
  "Return CREDENTIALS' nonempty secret-bearing values longest first."
  (stable-sort
   (remove-duplicates
    (remove-if-not
     #'non-empty-string-p
     (list
      (oauth-credentials-access-token credentials)
      (oauth-credentials-refresh-token credentials)
      (oauth-credentials-id-token credentials)
      (oauth-credentials-account-id credentials)))
    :test #'string=)
   #'>
   :key #'length))

(defun credentials-needs-refresh-p (credentials &key (window 300))
  "Return true when CREDENTIALS expire within WINDOW seconds."
  (let ((expiration (oauth-credentials-expires-at credentials)))
    (and expiration
         (<= expiration (+ (get-universal-time) window)))))


;;;; -- Unverified JWT Claims --

(defun jwt-payload (token)
  "Decode TOKEN's unverified JWT payload, returning NIL for malformed input."
  (handler-case
      (let* ((first-dot (position #\. token))
             (second-dot (and first-dot
                              (position #\. token :start (1+ first-dot)))))
        (when second-dot
          (let* ((encoded (subseq token (1+ first-dot) second-dot))
                 (decoded (cl-base64:base64-string-to-string
                           (padded-base64url encoded)
                           :uri t))
                 (payload (json-decode decoded)))
            (and (json-object-p payload) payload))))
    (error ()
      nil)))

(defun jwt-expiration (token)
  "Return TOKEN's unverified JWT expiration as universal time."
  (let* ((payload (jwt-payload token))
         (unix-expiration (and payload (json-get payload "exp"))))
    (when (integerp unix-expiration)
      (unix-time->universal-time unix-expiration))))

(defun jwt-subject (token)
  "Return TOKEN's unverified JWT subject claim, if present and non-empty."
  (let ((payload (jwt-payload token)))
    (when payload
      (let ((subject (json-get payload "sub")))
        (and (non-empty-string-p subject) subject)))))

(defun oauth-error-code (body)
  "Extract a non-secret OAuth error code from BODY, if possible."
  (handler-case
      (let ((document (and (stringp body) (json-decode body))))
        (when (json-object-p document)
          (let ((error-value (json-get document "error")))
            (let ((code
                    (cond
                      ((stringp error-value)
                       error-value)
                      ((json-object-p error-value)
                       (or (json-get error-value "code")
                           (json-get error-value "type")))
                      (t
                       nil))))
              (and (non-empty-string-p code)
                   (subseq code 0 (min 256 (length code))))))))
    (error ()
      nil)))


;;;; -- Credential Store Protocol --

(defclass credential-source ()
  ()
  (:documentation "One private storage location for OAuth credentials."))

(defclass credential-manager ()
  ()
  (:documentation "The store coordinating one provider's credential sources."))

(defgeneric credential-source-load (source)
  (:documentation "Load and return SOURCE's credentials, or NIL when absent."))

(defgeneric credential-source-save (source credentials)
  (:documentation "Durably persist CREDENTIALS to SOURCE."))

(defgeneric credential-source-pathname (source)
  (:documentation "Return the pathname SOURCE reads and writes."))

(defgeneric credential-source-label (source)
  (:documentation "Name SOURCE in user-visible failures."))

(defgeneric credential-manager-primary-source (manager)
  (:documentation "Return MANAGER's writable primary credential source."))

(defgeneric credential-manager-accept-account (manager credentials &key allow-change)
  (:documentation
   "Validate CREDENTIALS' account continuity before MANAGER persists them."))

(defmethod credential-manager-accept-account
    ((manager credential-manager) (credentials oauth-credentials)
     &key allow-change)
  "Accept any account by default."
  (declare (ignore manager allow-change))
  credentials)
