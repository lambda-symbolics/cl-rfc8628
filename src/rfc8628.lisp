(in-package #:cl-rfc8628)

;;;; -- The RFC 8628 Device Authorization Grant --

(defparameter *rfc8628-device-slow-down-increment* 5
  "Seconds added to the polling interval after an RFC 8628 slow_down error.")

(defclass rfc8628-device-authentication-client (device-authentication-client)
  ((device-code-path
    :initarg :device-code-path
    :reader rfc8628-device-authentication-client-device-code-path
    :type non-empty-string
    :documentation "The issuer-relative RFC 8628 device authorization path.")
   (token-path
    :initarg :token-path
    :reader rfc8628-device-authentication-client-token-path
    :type non-empty-string
    :documentation "The issuer-relative OAuth token path.")
   (scope
    :initarg :scope
    :reader rfc8628-device-authentication-client-scope
    :type non-empty-string
    :documentation "The space-delimited OAuth scopes requested by this client.")
   (request-code-parameters
    :initarg :request-code-parameters
    :initform nil
    :reader rfc8628-device-authentication-client-request-code-parameters
    :type list
    :documentation "Additional non-secret form parameters for device authorization."))
  (:documentation "A configurable RFC 8628 OAuth device authorization client."))

(defclass rfc8628-device-authorization (device-authorization)
  ((issued-at
    :initarg :issued-at
    :reader rfc8628-device-authorization-issued-at
    :type real
    :documentation "The monotonic time at which the device code was issued.")
   (expires-in
    :initarg :expires-in
    :reader rfc8628-device-authorization-expires-in
    :type (integer 1)
    :documentation "The server-reported device code lifetime in seconds."))
  (:documentation "One pending RFC 8628 device authorization and its lifetime."))


;;;; -- Provider Hooks --

(defgeneric rfc8628-device-authentication-authorization-class (client)
  (:documentation "Return the authorization class instantiated for CLIENT."))

(defmethod rfc8628-device-authentication-authorization-class
    ((client rfc8628-device-authentication-client))
  "Use the generic RFC 8628 authorization state by default."
  (declare (ignore client))
  'rfc8628-device-authorization)

(defgeneric rfc8628-device-authentication-validate-token-response
    (client document)
  (:documentation "Validate provider-specific claims in token DOCUMENT for CLIENT."))

(defmethod rfc8628-device-authentication-validate-token-response
    ((client rfc8628-device-authentication-client) (document hash-table))
  "Accept token documents without provider-specific claims by default."
  (declare (ignore client document))
  nil)

(defgeneric rfc8628-device-authentication-account-id (client document)
  (:documentation "Return the stable account identity carried by token DOCUMENT."))

(defmethod rfc8628-device-authentication-account-id
    ((client rfc8628-device-authentication-client) (document hash-table))
  "Resolve the account from the OpenID or access token subject claim."
  (declare (ignore client))
  (let ((id-token (json-get document "id_token"))
        (access-token (json-get document "access_token")))
    (or (and (stringp id-token) (jwt-subject id-token))
        (and (stringp access-token) (jwt-subject access-token)))))

(defgeneric rfc8628-device-authentication-publish-credentials
    (client manager credentials)
  (:documentation "Publish newly authorized CREDENTIALS through MANAGER."))

(defmethod rfc8628-device-authentication-publish-credentials
    ((client rfc8628-device-authentication-client)
     (manager credential-manager)
     (credentials oauth-credentials))
  "Publish CREDENTIALS to MANAGER's primary source."
  (declare (ignore client))
  (credential-manager-accept-account manager credentials :allow-change t)
  (credential-source-save
   (credential-manager-primary-source manager)
   credentials))


;;;; -- Request Code --

(defun rfc8628-device-authentication--valid-user-code-p (user-code)
  "Return true when USER-CODE contains only alphanumerics and hyphens."
  (if (every (lambda (character)
               (or (alphanumericp character)
                   (char= character #\-)))
             user-code)
      t
      nil))

(defun rfc8628-device-authentication--safe-verification-url-p (url)
  "Return true when URL is HTTPS or an exact local HTTP endpoint."
  (handler-case
      (let* ((parsed (quri:uri url))
             (scheme (quri:uri-scheme parsed))
             (host (quri:uri-host parsed)))
        (if (and (non-empty-string-p host)
                 (null (quri:uri-userinfo parsed))
                 (or (string-equal scheme "https")
                     (and (string-equal scheme "http")
                          (member host '("localhost" "127.0.0.1" "::1")
                                  :test #'string-equal))))
            t
            nil))
    (error ()
      nil)))

(defun rfc8628-device-authentication--request-code-parameters (client)
  "Return CLIENT's encoded device authorization form parameters."
  (append
   (list
    (cons "client_id" (device-authentication-client-id client))
    (cons "scope" (rfc8628-device-authentication-client-scope client)))
   (copy-tree
    (rfc8628-device-authentication-client-request-code-parameters client))))

(defmethod device-authentication-request-code
    ((client rfc8628-device-authentication-client))
  "Request a fresh RFC 8628 device code from CLIENT's issuer."
  (funcall
   *secret-region-function*
   (lambda ()
     (let* ((document
              (device-authentication-json-request
               :client client
               :url
               (device-authentication-issuer-url
                client
                (rfc8628-device-authentication-client-device-code-path client))
               :content-type "application/x-www-form-urlencoded"
               :content
               (quri:url-encode-params
                (rfc8628-device-authentication--request-code-parameters client))
               :stage ':request-code))
            (device-code (json-get document "device_code"))
            (user-code (json-get document "user_code"))
            (verification-uri (json-get document "verification_uri"))
            (verification-uri-complete
              (json-get document "verification_uri_complete"))
            (expires-in (json-get document "expires_in"))
            (interval (json-get document "interval")))
       (unless (and (non-empty-string-p device-code)
                    (non-empty-string-p user-code)
                    (rfc8628-device-authentication--valid-user-code-p user-code)
                    (non-empty-string-p verification-uri)
                    (integerp expires-in)
                    (plusp expires-in))
         (device-authentication-fail
          :stage ':request-code
          :message "The device authorization response omitted required fields."))
       (let ((verification-url
               (if (non-empty-string-p verification-uri-complete)
                   verification-uri-complete
                   verification-uri)))
         (unless (rfc8628-device-authentication--safe-verification-url-p
                  verification-url)
           (device-authentication-fail
            :stage ':request-code
            :message "The device authorization verification URL is not acceptable."))
         (make-instance
          (rfc8628-device-authentication-authorization-class client)
          :verification-url verification-url
          :user-code user-code
          :device-authorization-id device-code
          :poll-interval
          (device-authentication-poll-interval (or interval 5))
          :issued-at
          (funcall (device-authentication-client-clock-function client))
          :expires-in expires-in))))))


;;;; -- Poll and Completion --

(defun rfc8628-device-authentication-poll-for-tokens (client authorization)
  "Poll CLIENT's token endpoint until AUTHORIZATION succeeds, fails, or expires."
  (let* ((clock (device-authentication-client-clock-function client))
         (deadline
           (+ (rfc8628-device-authorization-issued-at authorization)
              (min (device-authentication-client-poll-timeout client)
                   (rfc8628-device-authorization-expires-in authorization))))
         (interval (device-authorization-poll-interval authorization))
         (url
           (device-authentication-issuer-url
            client
            (rfc8628-device-authentication-client-token-path client)))
         (content
           (quri:url-encode-params
            (list
             (cons "grant_type"
                   "urn:ietf:params:oauth:grant-type:device_code")
             (cons "device_code" (device-authorization-id authorization))
             (cons "client_id" (device-authentication-client-id client))))))
    (loop
      ;; Sleep before polling: an immediate poll on a fresh code only returns
      ;; authorization_pending and can trigger a slow_down response.
      (let ((now (funcall clock)))
        (when (>= now deadline)
          (device-authentication-fail
           :stage ':poll
           :message "Device authentication timed out before approval."))
        (funcall (device-authentication-client-sleep-function client)
                 (min interval (- deadline now)))
        (when (>= (funcall clock) deadline)
          (device-authentication-fail
           :stage ':poll
           :message "Device authentication timed out before approval.")))
      (multiple-value-bind (body status response-headers)
          (device-authentication-invoke-request
           :client client
           :url url
           :headers
           (list (cons "Content-Type" "application/x-www-form-urlencoded")
                 (cons "Accept" "application/json")
                 (cons "User-Agent" (device-authentication-user-agent)))
           :content content
           :stage ':poll)
        (declare (ignore response-headers))
        (if (device-authentication-success-status-p status)
            (let ((document
                    (handler-case
                        (json-decode body)
                      (error ()
                        (device-authentication-fail
                         :stage ':poll
                         :message
                         "The approved device response contained invalid JSON.")))))
              (unless (json-object-p document)
                (device-authentication-fail
                 :stage ':poll
                 :message
                 "The approved device response was not a JSON object."))
              (return document))
            (let ((code
                    (device-authentication-error-code-of-body
                     body
                     (list (device-authorization-id authorization) content))))
              (cond
                ((equal code "authorization_pending")
                 nil)
                ((equal code "slow_down")
                 (incf interval *rfc8628-device-slow-down-increment*))
                ((equal code "access_denied")
                 (device-authentication-fail
                  :stage ':poll
                  :message "The authorization request was denied."
                  :status status
                  :code code))
                ((equal code "expired_token")
                 (device-authentication-fail
                  :stage ':poll
                  :message "The device code expired before approval."
                  :status status
                  :code code))
                (t
                 (device-authentication-fail
                  :stage ':poll
                  :message
                  (format nil
                          "Device authorization was not completed~@[ (~A)~]."
                          code)
                  :status status
                  :code code)))))))))

(defun rfc8628-device-authentication--credentials
    (client document source-path)
  "Return renewable OAuth credentials carried by token DOCUMENT for SOURCE-PATH."
  (rfc8628-device-authentication-validate-token-response client document)
  (let* ((access-token (json-get document "access_token"))
         (refresh-token (json-get document "refresh_token"))
         (id-token (json-get document "id_token"))
         (expires-in (json-get document "expires_in"))
         (account-id
           (rfc8628-device-authentication-account-id client document)))
    (unless (and (non-empty-string-p access-token)
                 (non-empty-string-p refresh-token)
                 (non-empty-string-p account-id))
      (device-authentication-fail
       :stage ':credentials
       :message "The device token response omitted required credential fields."))
    (make-instance
     'oauth-credentials
     :access-token access-token
     :refresh-token refresh-token
     :id-token (and (non-empty-string-p id-token) id-token)
     :account-id account-id
     :expires-at
     (or (and (integerp expires-in)
              (plusp expires-in)
              (+ (get-universal-time) expires-in))
         (jwt-expiration access-token))
     :source-path source-path)))

(defmethod device-authentication-complete
    ((client rfc8628-device-authentication-client)
     (authorization rfc8628-device-authorization)
     (manager credential-manager))
  "Poll AUTHORIZATION and securely publish the resulting OAuth credentials."
  (funcall
   *secret-region-function*
   (lambda ()
     (let* ((document
              (funcall
               (device-authentication-client-poll-function client)
               client
               authorization))
            (primary-source (credential-manager-primary-source manager)))
       (unless (json-object-p document)
         (device-authentication-fail
          :stage ':poll
          :message "The device authorization poll returned an invalid result."))
       (rfc8628-device-authentication-publish-credentials
        client
        manager
        (rfc8628-device-authentication--credentials
         client
         document
         (credential-source-pathname primary-source)))
       t))))
