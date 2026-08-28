(in-package #:cl-rfc8628)

;;;; -- Hooks and Defaults --

(defparameter *device-authentication-timeout* 900
  "The maximum number of seconds allowed for device authorization.")

(defparameter *device-authentication-redaction-marker*
  "[DEVICE CREDENTIAL REDACTED]"
  "The preferred replacement for echoed device-flow credential material.")

(defparameter *secret-region-function* #'funcall
  "The wrapper invoked around every code path holding secret material.

Host applications with credential-scoping machinery replace this with
their own region function of one thunk argument.")

(defparameter *user-agent-function*
  (lambda ()
    (format nil "cl-rfc8628 (~A ~A; ~A)"
            (software-type)
            (software-version)
            (machine-type)))
  "The function returning the User-Agent sent to device endpoints.")

(defparameter *device-authentication-error-class*
  'device-authentication-error
  "The condition class signaled for device authentication failures.

Host applications may substitute a subclass of DEVICE-AUTHENTICATION-ERROR
to join their own condition hierarchy.")


;;;; -- Conditions --

(define-condition device-authentication-error (error)
  ((message
    :initarg :message
    :reader device-authentication-error-message
    :type string
    :documentation "The complete non-secret failure description.")
   (stage
    :initarg :stage
    :reader device-authentication-error-stage
    :type keyword
    :documentation "The device flow stage that failed.")
   (status
    :initarg :status
    :initform nil
    :reader device-authentication-error-status
    :type (option integer)
    :documentation "The HTTP status associated with the failure, if known.")
   (code
    :initarg :code
    :initform nil
    :reader device-authentication-error-code
    :type (option string)
    :documentation "A bounded non-secret OAuth error code, if supplied."))
  (:report (lambda (condition stream)
             (write-string (device-authentication-error-message condition)
                           stream)))
  (:documentation "A safe, structured failure in device authentication."))

(defun device-authentication-fail (&key stage message status code)
  "Signal a structured device authentication failure without secret material."
  (error *device-authentication-error-class*
         :message message
         :stage stage
         :status status
         :code code))


;;;; -- Device Authentication State --

(defclass device-authorization ()
  ((verification-url
    :initarg :verification-url
    :reader device-authorization-verification-url
    :type non-empty-string
    :documentation "The URL at which the user approves this authorization.")
   (user-code
    :initarg :user-code
    :reader device-authorization-user-code
    :type non-empty-string
    :documentation "The one-time code displayed to the user.")
   (device-authorization-id
    :initarg :device-authorization-id
    :reader device-authorization-id
    :type non-empty-string
    :documentation "The opaque server identifier used only while polling.")
   (poll-interval
    :initarg :poll-interval
    :reader device-authorization-poll-interval
    :type (integer 1)
    :documentation "The server-requested number of seconds between polls."))
  (:documentation "The non-credential state of one pending device authorization."))

(defclass device-authentication-client ()
  ((issuer
    :initarg :issuer
    :reader device-authentication-client-issuer
    :type non-empty-string
    :documentation "The OAuth issuer, without a trailing slash.")
   (client-id
    :initarg :client-id
    :reader device-authentication-client-id
    :type non-empty-string
    :documentation "The public OAuth client identifier.")
   (request-function
    :initarg :request-function
    :reader device-authentication-client-request-function
    :type function
    :documentation "The injected HTTP request function.")
   (poll-function
    :initarg :poll-function
    :reader device-authentication-client-poll-function
    :type function
    :documentation "The injected authorization polling function.")
   (sleep-function
    :initarg :sleep-function
    :initform #'sleep
    :reader device-authentication-client-sleep-function
    :type function
    :documentation "The injected interruptible sleep function.")
   (clock-function
    :initarg :clock-function
    :initform #'device-authentication-monotonic-seconds
    :reader device-authentication-client-clock-function
    :type function
    :documentation "The injected monotonic clock function returning seconds.")
   (browser-function
    :initarg :browser-function
    :initform #'device-authentication-open-browser
    :reader device-authentication-client-browser-function
    :type function
    :documentation "The injected best-effort browser opening function.")
   (poll-timeout
    :initarg :poll-timeout
    :initform *device-authentication-timeout*
    :reader device-authentication-client-poll-timeout
    :type (integer 1)
    :documentation "The maximum number of seconds spent polling."))
  (:documentation "Replaceable effects and endpoints for device authentication."))


;;;; -- Device Authentication Protocol --

(defgeneric device-authentication-request-code (client)
  (:documentation
   "Start device authentication through CLIENT and return its public code."))

(defgeneric device-authentication-complete (client authorization manager)
  (:documentation
   "Complete AUTHORIZATION and publish credentials through MANAGER's private store."))

(defgeneric device-authentication-login (client manager &key stream open-browser-p)
  (:documentation
   "Run the complete device flow, always displaying the URL and code on STREAM."))

(defgeneric device-authentication-display-code (client authorization stream)
  (:documentation
   "Display AUTHORIZATION's public URL and code on STREAM, then flush it."))

(defmethod device-authentication-display-code
    ((client device-authentication-client)
     (authorization device-authorization)
     (stream stream))
  "Display the verification URL and one-time code."
  (declare (ignore client))
  (format stream
          "~&Sign in:~%  Open: ~A~%  Code: ~A~%~%Continue only if you started this login yourself.~%"
          (device-authorization-verification-url authorization)
          (device-authorization-user-code authorization))
  (finish-output stream)
  nil)

(defmethod device-authentication-login
    ((client device-authentication-client)
     (manager credential-manager)
     &key
       (stream *standard-output*)
       (open-browser-p t))
  "Run device authentication while keeping every credential off STREAM."
  (funcall
   *secret-region-function*
   (lambda ()
     (let ((authorization (device-authentication-request-code client)))
       (device-authentication-display-code client authorization stream)
       (when open-browser-p
         (handler-case
             (funcall (device-authentication-client-browser-function client)
                      (device-authorization-verification-url authorization))
           (error ()
             nil)))
       (device-authentication-complete client authorization manager)))))

(defun device-authentication-open-browser (url)
  "Try to open URL with the platform browser and return whether launch succeeded."
  (handler-case
      (let ((command
              (cond
                ((uiop:os-windows-p)
                 (list "rundll32" "url.dll,FileProtocolHandler" url))
                ((uiop:os-macosx-p)
                 (list "open" url))
                (t
                 (list "xdg-open" url)))))
        (uiop:launch-program command
                             :input nil
                             :output nil
                             :error-output nil
                             :ignore-error-status t)
        t)
    (error ()
      nil)))


;;;; -- Transport --

(defun device-authentication-issuer-url (client path)
  "Return CLIENT's issuer joined to absolute PATH."
  (concatenate 'string
               (device-authentication-client-issuer client)
               path))

(defun device-authentication-user-agent ()
  "Return the User-Agent sent to device endpoints."
  (funcall *user-agent-function*))

(defun device-authentication-request (&key method url headers content)
  "Perform one device-flow HTTP request and return body, status, and headers."
  (unless (eq method :post)
    (device-authentication-fail
     :stage ':transport
     :message "Device authentication supports only HTTP POST requests."))
  (handler-case
      (multiple-value-bind (body status response-headers)
          (dexador:post url
                        :headers headers
                        :content content
                        :force-string t
                        :keep-alive nil
                        :connect-timeout 30
                        :read-timeout 60)
        (values body status response-headers))
    (dexador.error:http-request-failed (condition)
      (values (or (dexador.error:response-body condition) "")
              (dexador.error:response-status condition)
              (dexador.error:response-headers condition)))))

(defun device-authentication-invoke-request
    (&key client url headers content stage)
  "Invoke CLIENT's request effect and normalize transport failures for STAGE."
  (handler-case
      (multiple-value-bind (body status response-headers)
          (funcall (device-authentication-client-request-function client)
                   :method ':post
                   :url url
                   :headers headers
                   :content content)
        (unless (and (stringp body) (integerp status))
          (device-authentication-fail
           :stage stage
           :message "The device authentication transport returned an invalid response."))
        (values body status response-headers))
    (device-authentication-error (condition)
      (error condition))
    (error ()
      (device-authentication-fail
       :stage stage
       :message "The device authentication transport failed."))))

(defun device-authentication-error-code-of-body (body secret-values)
  "Return BODY's OAuth error code with exact SECRET-VALUES removed."
  (let ((code (oauth-error-code body))
        (secrets
          (stable-sort
           (remove-duplicates
            (remove-if-not #'non-empty-string-p secret-values)
            :test #'string=)
           #'>
           :key #'length)))
    (and
     code
     (redact-exact-string-values
      code
      secrets
      (safe-redaction-marker
       *device-authentication-redaction-marker*
       secrets)))))

(defun device-authentication-success-status-p (status)
  "Return true when STATUS is an HTTP success status."
  (if (<= 200 status 299) t nil))

(defun device-authentication-json-request
    (&key client url content-type content stage secret-values)
  "POST CONTENT to URL and return its validated JSON object for STAGE."
  (multiple-value-bind (body status response-headers)
      (device-authentication-invoke-request
       :client client
       :url url
       :headers (list (cons "Content-Type" content-type)
                      (cons "Accept" "application/json")
                      (cons "User-Agent"
                            (device-authentication-user-agent)))
       :content content
       :stage stage)
    (declare (ignore response-headers))
    (unless (device-authentication-success-status-p status)
      (let ((code
              (device-authentication-error-code-of-body
               body secret-values)))
        (device-authentication-fail
         :stage stage
         :message (if (and (eq stage :request-code) (= status 404))
                      "Device authentication is unavailable for this issuer."
                      (format nil "Device authentication failed during ~A~@[ (~A)~]."
                              stage
                              code))
         :status status
         :code code)))
    (handler-case
        (let ((document (json-decode body)))
          (if (json-object-p document)
              document
              (device-authentication-fail
               :stage stage
               :message "The device authentication response was not a JSON object.")))
      (device-authentication-error (condition)
        (error condition))
      (error ()
        (device-authentication-fail
         :stage stage
         :message "The device authentication response contained invalid JSON.")))))

(defun device-authentication-poll-interval (value)
  "Return VALUE as a positive whole-second polling interval."
  (let ((interval
          (cond
            ((integerp value)
             value)
            ((stringp value)
             (let ((trimmed (string-trim '(#\Space #\Tab #\Newline #\Return)
                                         value)))
               (multiple-value-bind (parsed end)
                   (parse-integer trimmed :junk-allowed t)
                 (and parsed (= end (length trimmed)) parsed))))
            (t
             nil))))
    (unless (and interval (plusp interval))
      (device-authentication-fail
       :stage ':request-code
       :message "The device authorization response contained an invalid polling interval."))
    interval))

(defun device-authentication-monotonic-seconds ()
  "Return monotonically increasing process time in seconds."
  (/ (get-internal-real-time)
     internal-time-units-per-second))
