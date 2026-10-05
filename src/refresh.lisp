(in-package #:cl-rfc8628)

;;;; -- Refresh Grant Defaults --

(defparameter *refresh-redaction-marker* "[OAUTH CREDENTIAL REDACTED]"
  "The preferred replacement for credential material echoed by a token endpoint.")

(defparameter *refresh-form-content-type* "application/x-www-form-urlencoded"
  "The RFC 6749 token request media type.")

(defparameter *refresh-json-content-type* "application/json"
  "The media type of token endpoints that accept a JSON request object.")


;;;; -- Refresh Grant Credential Manager --

(defclass refresh-grant-credential-manager (managed-credential-manager)
  ()
  (:documentation
   "A managed credential manager rotating tokens with the RFC 6749 refresh grant.

Subclasses name their token endpoint and client, and may adjust the request
parameters, headers, encoding, transport, returned account claims, and
response validation through the generic functions below."))


(defgeneric credential-manager-token-endpoint (manager)
  (:documentation "Return the token endpoint URL receiving MANAGER's refresh grants."))


(defgeneric credential-manager-client-id (manager)
  (:documentation "Return the public OAuth client identifier MANAGER refreshes as."))


(defgeneric credential-manager-refresh-parameters (manager refresh-token)
  (:documentation
   "Return the alist of request parameters spending REFRESH-TOKEN at MANAGER's endpoint."))


(defmethod credential-manager-refresh-parameters
    ((manager refresh-grant-credential-manager) (refresh-token string))
  "Return the RFC 6749 section 6 grant type, refresh token, and client identifier."
  (list (cons "grant_type" "refresh_token")
        (cons "refresh_token" refresh-token)
        (cons "client_id" (credential-manager-client-id manager))))


(defgeneric credential-manager-refresh-headers (manager refresh-token)
  (:documentation
   "Return extra request headers for spending REFRESH-TOKEN beyond the content type,
Accept, and User-Agent headers every refresh request carries."))


(defmethod credential-manager-refresh-headers
    ((manager refresh-grant-credential-manager) (refresh-token string))
  "Send no extra headers."
  (declare (ignore manager refresh-token))
  nil)


(defgeneric credential-manager-refresh-content-type (manager)
  (:documentation
   "Return *REFRESH-FORM-CONTENT-TYPE* or *REFRESH-JSON-CONTENT-TYPE* for MANAGER's requests."))


(defmethod credential-manager-refresh-content-type
    ((manager refresh-grant-credential-manager))
  "Form-encode refresh requests as RFC 6749 specifies."
  (declare (ignore manager))
  *refresh-form-content-type*)


(defgeneric credential-manager-refresh-request (manager &key url headers content)
  (:documentation
   "POST CONTENT with HEADERS to URL and return the body, HTTP status, and headers.

An HTTP error status is returned rather than signaled. Hosts specialize this to
add their own deadline or transport."))


(defmethod credential-manager-refresh-request
    ((manager refresh-grant-credential-manager) &key url headers content)
  "POST through the shared device-flow transport."
  (declare (ignore manager))
  (device-authentication-request :method ':post :url url :headers headers
                                 :content content))


(defgeneric credential-manager-refreshed-account-ids (manager document)
  (:documentation
   "Return the account identities claimed by the tokens in refresh DOCUMENT.

Each one must match the manager's account, and an empty list keeps it."))


(defmethod credential-manager-refreshed-account-ids
    ((manager refresh-grant-credential-manager) document)
  "Return the subjects of DOCUMENT's OpenID and access tokens."
  (declare (ignore manager))
  (loop for key in '("id_token" "access_token")
        for token = (json-get document key)
        for subject = (and (stringp token) (jwt-subject token))
        when subject
          collect subject))


(defgeneric credential-manager-validate-refresh-response (manager document credentials)
  (:documentation
   "Signal *TOKEN-REFRESH-FAILED-CLASS* unless refresh DOCUMENT satisfies MANAGER.

CREDENTIALS are the ones being refreshed. The return value is ignored."))


(defmethod credential-manager-validate-refresh-response
    ((manager refresh-grant-credential-manager) document (credentials oauth-credentials))
  "Require nothing beyond the RFC 6749 access token."
  (declare (ignore manager document credentials))
  nil)


(defmethod credential-manager-refresh-exchange
    ((manager refresh-grant-credential-manager)
     (credentials oauth-credentials)
     (refresh-token string))
  "Spend REFRESH-TOKEN at MANAGER's token endpoint and return account-continuous credentials.

When the endpoint rejects the token and the primary source already holds a newer
rotation, that rotation is returned unpublished instead of signaling."
  (let* ((parameters (credential-manager-refresh-parameters manager refresh-token))
         (content-type (credential-manager-refresh-content-type manager)))
    (multiple-value-bind (body status)
        (refresh-grant--request
         manager
         :url (credential-manager-token-endpoint manager)
         :headers (append (list (cons "Content-Type" content-type)
                                (cons "Accept" "application/json")
                                (cons "User-Agent" (device-authentication-user-agent)))
                          (credential-manager-refresh-headers manager refresh-token))
         :content (refresh-grant--encode content-type parameters))
      (if (device-authentication-success-status-p status)
          (values (credential-manager-refresh-response-credentials manager credentials body)
                  t)
          (let ((code (refresh-grant--redacted-error-code
                       body (cons refresh-token
                                  (oauth-credentials-secret-values credentials))))
                (newer (credential-manager-newer-rotation manager refresh-token)))
            (if newer
                (values newer nil)
                (error *token-refresh-failed-class*
                       :message (format nil "~A OAuth token refresh failed~@[ (~A)~]; ~A."
                                        (credential-manager-provider-label manager)
                                        code
                                        (credential-manager-login-hint manager))
                       :status status
                       :response code)))))))


(defun credential-manager-refresh-response-credentials (manager credentials body)
  "Validate refresh response BODY and return credentials continuing CREDENTIALS.

A missing refresh or OpenID token keeps the previous one, and expiry comes from
expires_in or else the access token's own claim. Signal
*TOKEN-REFRESH-FAILED-CLASS* when BODY is malformed, fails MANAGER's validation,
or claims a different account."
  (let ((label (credential-manager-provider-label manager)))
    (flet ((fail (control)
             (error *token-refresh-failed-class*
                    :message (format nil control label) :status nil :response nil)))
      (let ((document (handler-case (json-decode body) (error () nil))))
        (unless (json-object-p document)
          (fail "The ~A OAuth refresh response was malformed."))
        (let ((access-token (json-get document "access_token"))
              (id-token (json-get document "id_token"))
              (refresh-token (or (json-get document "refresh_token")
                                 (oauth-credentials-refresh-token credentials)))
              (expires-in (json-get document "expires_in"))
              (account-id (oauth-credentials-account-id credentials)))
          (unless (and (non-empty-string-p access-token)
                       (non-empty-string-p refresh-token)
                       (or (null id-token) (non-empty-string-p id-token)))
            (fail "The ~A OAuth refresh response omitted required fields."))
          (credential-manager-validate-refresh-response manager document credentials)
          (unless (every (lambda (claimed) (equal claimed account-id))
                         (credential-manager-refreshed-account-ids manager document))
            (fail "The ~A OAuth refresh response changed accounts."))
          (make-instance 'oauth-credentials
                         :access-token access-token
                         :refresh-token refresh-token
                         :id-token (or id-token (oauth-credentials-id-token credentials))
                         :account-id account-id
                         :expires-at (if (and (integerp expires-in) (plusp expires-in))
                                         (+ (get-universal-time) expires-in)
                                         (jwt-expiration access-token))
                         :source-path (credential-source-pathname
                                       (credential-manager-primary-source manager))))))))


(defun refresh-grant--request (manager &key url headers content)
  "Invoke MANAGER's refresh transport, returning only a string body and integer status.

Host credential conditions propagate, and any other failure becomes a refresh failure."
  (flet ((fail (control)
           (error *token-refresh-failed-class*
                  :message (format nil control (credential-manager-provider-label manager))
                  :status nil :response nil)))
    (multiple-value-bind (body status)
        (handler-case
            (credential-manager-refresh-request manager :url url :headers headers
                                                        :content content)
          (error (condition)
            (if (or (typep condition 'credential-error)
                    (typep condition *credential-error-class*))
                (error condition)
                (fail "~A OAuth token refresh could not be completed."))))
      (unless (and (stringp body) (integerp status))
        (fail "The ~A OAuth refresh transport returned an invalid response."))
      (values body status))))


(defun refresh-grant--encode (content-type parameters)
  "Encode PARAMETERS as CONTENT-TYPE's request body."
  (if (string= content-type *refresh-json-content-type*)
      (json-encode (let ((object (json-object)))
                     (loop for (name . value) in parameters
                           do (setf (gethash name object) value))
                     object))
      (quri:url-encode-params parameters)))


(defun refresh-grant--redacted-error-code (body secrets)
  "Return BODY's bounded OAuth error code with every exact secret in SECRETS removed."
  (let ((code (oauth-error-code body))
        (secrets (stable-sort (remove-duplicates (remove-if-not #'non-empty-string-p secrets)
                                                 :test #'string=)
                              #'> :key #'length)))
    (and code
         (redact-exact-string-values
          code secrets (safe-redaction-marker *refresh-redaction-marker* secrets)))))
