(in-package #:cl-rfc8628)


;;;; -- Environment Credential Sources --

(defclass environment-credential-source (credential-source)
  ((environment-variable
    :initarg :environment-variable
    :reader environment-credential-source-environment-variable
    :type string
    :documentation "The environment variable holding the static credential.")
   (account-id
    :initarg :account-id
    :reader environment-credential-source-account-id
    :type string
    :documentation "The synthetic account identifier pinned for the credential.")
   (pathname
    :initarg :pathname
    :initform nil
    :reader environment-credential-source--pathname
    :documentation "The path reported for this source, or NIL; the environment has none."))
  (:documentation
   "A read-only source loading one static credential, such as an API key, from the environment."))

(defmethod credential-source-pathname ((source environment-credential-source))
  "Return the reporting path the host supplied for SOURCE, or NIL."
  (environment-credential-source--pathname source))

(defmethod credential-source-label ((source environment-credential-source))
  "Name the environment variable in user-visible failures."
  (format nil "the ~A environment variable"
          (environment-credential-source-environment-variable source)))

(defmethod credential-source-load ((source environment-credential-source))
  "Return SOURCE's credential from its environment variable, or NIL when unset or empty."
  (let ((value (uiop:getenv (environment-credential-source-environment-variable source))))
    (when (and (stringp value) (plusp (length value)))
      (make-instance 'oauth-credentials
                     :access-token value
                     :refresh-token nil
                     :id-token nil
                     :account-id (environment-credential-source-account-id source)
                     :expires-at nil
                     :source-path (credential-source-pathname source)))))

(defmethod credential-source-save ((source environment-credential-source) credentials)
  "Refuse to write SOURCE, because the environment is read-only."
  (declare (ignore credentials))
  (error *credential-error-class*
         :message (format nil "The ~A environment source is read-only."
                          (environment-credential-source-environment-variable source))))


;;;; -- Static Credential Managers --

(defclass static-credential-manager (managed-credential-manager)
  ()
  (:documentation
   "A manager for static credentials, such as API keys, that never refresh.

Its bootstrap source, typically an ENVIRONMENT-CREDENTIAL-SOURCE, takes
precedence over the stored primary credential while it holds a value."))

(defmethod credential-manager-load ((manager static-credential-manager))
  "Load the bootstrap credential when present, then the primary one."
  (let ((bootstrap (credential-manager-bootstrap-source manager))
        (primary (credential-manager-primary-source manager)))
    (credential-manager-accept-account
     manager
     (or (and bootstrap (credential-source-load bootstrap))
         (credential-source-load primary)
         (error *credentials-unavailable-class*
                :message (format nil "No ~A ~A is available; ~A."
                                 (credential-manager-provider-label manager)
                                 (credential-manager-credential-description manager)
                                 (credential-manager-login-hint manager))
                :searched-paths (remove nil (list (credential-source-pathname primary))))))))

(defmethod credential-manager-refreshable-p ((manager static-credential-manager))
  "Static credentials cannot refresh."
  (declare (ignore manager))
  nil)

(defmethod credential-manager-credential-description ((manager static-credential-manager))
  "Describe static credentials as API keys."
  (declare (ignore manager))
  "API key")
