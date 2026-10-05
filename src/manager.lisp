(in-package #:cl-rfc8628)


;;;; -- Credential Failures --

(define-condition credential-error (error)
  ((message :initarg :message :reader credential-error-message
            :documentation "The non-secret explanation of the failure."))
  (:report (lambda (condition stream)
             (write-string (credential-error-message condition) stream)))
  (:documentation "A credential lifecycle failure without retained secrets."))


(define-condition credentials-unavailable (credential-error)
  ((searched-paths :initarg :searched-paths
                   :reader credentials-unavailable-searched-paths
                   :documentation "The source paths inspected for credentials."))
  (:documentation "No usable primary or bootstrap credentials were found."))


(define-condition token-refresh-failed (credential-error)
  ((status :initarg :status :initform nil :reader token-refresh-failed-status
           :documentation "An optional HTTP status supplied by the exchange.")
   (response :initarg :response :initform nil :reader token-refresh-failed-response
             :documentation "An optional bounded, non-secret OAuth error code."))
  (:documentation "Credentials could not be refreshed."))


(defparameter *credential-error-class* 'credential-error
  "The condition class used for account-continuity failures.")


(defparameter *credentials-unavailable-class* 'credentials-unavailable
  "The condition class used when credential sources are unavailable.")


(defparameter *token-refresh-failed-class* 'token-refresh-failed
  "The condition class used when the manager cannot refresh credentials.")


;;;; -- Credential Manager --

(defclass credential-refresh-generation ()
  ((number
    :initarg :number
    :reader credential-refresh-generation-number
    :type (integer 1)
    :documentation "The manager-local sequence number for this refresh attempt.")
   (lock
    :initform (make-lock "OAuth refresh generation")
    :reader credential-refresh-generation-lock
    :documentation "The lock protecting this generation's terminal outcome.")
   (completion
    :initform (make-condition-variable :name "OAuth refresh generation completion")
    :reader credential-refresh-generation-completion
    :documentation "The condition variable notified when this generation terminates.")
   (completed-p
    :initform nil
    :accessor credential-refresh-generation-completed-p
    :type boolean
    :documentation "Whether this generation has reached an immutable terminal outcome.")
   (outcome-kind
    :initform nil
    :accessor credential-refresh-generation-outcome-kind
    :type (member nil :success :failure :abandoned)
    :documentation "The immutable terminal outcome kind, or NIL before completion.")
   (result
    :initform nil
    :accessor credential-refresh-generation-result
    :type (option oauth-credentials)
    :documentation "The successful credential result shared by every waiter.")
   (failure
    :initform nil
    :accessor credential-refresh-generation-failure
    :type (option condition)
    :documentation "The typed failure shared by every waiter after failure.")
   (waiter-count
    :initform 0
    :accessor credential-refresh-generation-waiter-count
    :type (integer 0)
    :documentation "The number of callers currently awaiting this generation."))
  (:documentation "One immutable, independently waitable OAuth refresh outcome."))


(defclass managed-credential-manager (credential-manager)
  ((primary-source
    :initarg :primary-source
    :reader credential-manager-primary-source
    :type credential-source
    :documentation "The host's writable credential source.")
   (bootstrap-source
    :initarg :bootstrap-source
    :initform nil
    :reader credential-manager-bootstrap-source
    :type (option credential-source)
    :documentation "The optional read-only bootstrap source.")
   (refresh-lock
    :initform (make-lock "OAuth refresh")
    :reader credential-manager-refresh-lock
    :documentation "The in-process serialization lock for token rotation.")
   (refresh-in-progress-p
    :initform nil
    :accessor credential-manager--refresh-in-progress-p
    :type boolean
    :documentation "Whether one thread is exchanging this manager's refresh token.")
   (refresh-completion
    :initform (make-condition-variable :name "OAuth refresh completion")
    :reader credential-manager--refresh-completion
    :documentation "The condition variable notified after manager refresh-state changes.")
   (refresh-epoch
    :initform 0
    :accessor credential-manager--refresh-epoch
    :type (integer 0)
    :documentation "The monotonically increasing in-process refresh generation.")
   (refresh-generation
    :initform nil
    :accessor credential-manager--refresh-generation
    :type (option credential-refresh-generation)
    :documentation "The current in-process refresh generation, when one exists.")
   (account-lock
    :initform (bordeaux-threads:make-recursive-lock "OAuth account continuity")
    :reader credential-manager--account-lock
    :documentation "Serialize account checks and publication against explicit repinning.")
   (account-id
    :initform nil
    :accessor credential-manager-account-id
    :type (option string)
    :documentation "The account identity pinned for this manager's lifetime."))
  (:documentation "Credential paths and refresh policy without retained tokens."))


(defgeneric credential-manager-provider-label (manager)
  (:documentation "Return the short user-visible name of MANAGER's account service."))


(defgeneric credential-manager-login-hint (manager)
  (:documentation "Return the imperative login instruction for MANAGER's service."))


(defgeneric credential-manager-credential-description (manager)
  (:documentation "Return the user-visible kind of credential managed by MANAGER."))


(defmethod credential-manager-credential-description ((manager managed-credential-manager))
  "Describe OAuth and other non-key credentials generically."
  (declare (ignore manager))
  "credentials")


(defgeneric credential-manager-refreshable-p (manager)
  (:documentation "Return true when MANAGER can refresh rejected credentials."))


(defmethod credential-manager-refreshable-p ((manager managed-credential-manager))
  "OAuth credential managers support bounded token refresh."
  (declare (ignore manager))
  t)


(defgeneric credential-manager-refresh-exchange (manager credentials refresh-token)
  (:documentation
   "Exchange REFRESH-TOKEN for rotated CREDENTIALS at MANAGER's OAuth service.

The first value is the account-continuous refreshed credentials. The second
value is true when the caller must publish them to the primary store, and
false when a sibling process already published an equivalent rotation."))


(defgeneric credential-manager-validate-credentials (manager credentials)
  (:documentation
   "Return stored CREDENTIALS once MANAGER accepts them for requests, or signal.

The manager applies this to every primary-source credential it loads or adopts
from a sibling's rotation, so provider claim requirements hold for both."))


(defmethod credential-manager-validate-credentials
    ((manager managed-credential-manager) (credentials oauth-credentials))
  "Accept stored credentials without provider-specific claim checks."
  (declare (ignore manager))
  credentials)


(defgeneric credential-manager-call-with-refresh-lock (manager function)
  (:documentation
   "Call FUNCTION while MANAGER holds the lock serializing its token rotation.

A refresh leader rereads the primary source, exchanges the refresh token, and
publishes the rotation inside this lock, so a manager whose refresh tokens are
single-use supplies a lock shared by every process using the same store. The
default serializes only this manager's threads, which its in-process refresh
generation already does."))


(defmethod credential-manager-call-with-refresh-lock
    ((manager managed-credential-manager) (function function))
  "Call FUNCTION without a cross-process lock."
  (declare (ignore manager))
  (funcall function))


(defgeneric credential-manager--refresh-generation-installed (manager generation)
  (:documentation
   "Observe that MANAGER published GENERATION before its refresh exchange begins."))


(defmethod credential-manager--refresh-generation-installed
    ((manager managed-credential-manager) (generation credential-refresh-generation))
  "Provide a no-op refresh-leader publication hook."
  (declare (ignore manager generation))
  nil)


(defmethod credential-manager-accept-account
    ((manager managed-credential-manager) (credentials oauth-credentials)
     &key allow-change)
  "Pin CREDENTIALS' account, rejecting an unexplained account change atomically."
  (bordeaux-threads:with-recursive-lock-held ((credential-manager--account-lock manager))
    (let ((expected (credential-manager-account-id manager))
          (actual (oauth-credentials-account-id credentials)))
      (when (and expected (not allow-change) (not (string= expected actual)))
        (error *credential-error-class*
               :message
               (format nil "The ~A credential account changed during this manager's lifetime."
                       (credential-manager-provider-label manager))))
      (setf (credential-manager-account-id manager) actual)
      credentials)))


(defun credential-manager-import-bootstrap (manager bootstrap)
  "Import only BOOTSTRAP's access token, unless a primary writer already won."
  (with-lock-held ((credential-manager-refresh-lock manager))
    (let* ((primary-source (credential-manager-primary-source manager))
           (latest (credential-source-load primary-source)))
      (when latest
        (return-from credential-manager-import-bootstrap
          (credential-manager-accept-account manager latest)))
      (when (credentials-needs-refresh-p bootstrap :window 0)
        (error *credentials-unavailable-class*
               :message (format nil "The ~A bootstrap access token expired; ~A."
                                (credential-source-label
                                 (credential-manager-bootstrap-source manager))
                                (credential-manager-login-hint manager))
               :searched-paths (list (credential-source-pathname
                                      (credential-manager-bootstrap-source manager)))))
      (let ((imported
              (make-instance 'oauth-credentials
                             :access-token (oauth-credentials-access-token bootstrap)
                             :refresh-token nil
                             :id-token nil
                             :account-id (oauth-credentials-account-id bootstrap)
                             :expires-at (oauth-credentials-expires-at bootstrap)
                             :source-path (credential-source-pathname primary-source))))
        (bordeaux-threads:with-recursive-lock-held ((credential-manager--account-lock manager))
          (credential-manager-accept-account manager imported)
          (credential-source-save primary-source imported))
        imported))))


(defgeneric credential-manager-load (manager)
  (:documentation
   "Load request credentials from MANAGER's provider-specific sources."))


(defmethod credential-manager-load ((manager managed-credential-manager))
  "Load primary credentials, importing a bootstrap source when configured."
  (let* ((primary-source (credential-manager-primary-source manager))
         (bootstrap-source (credential-manager-bootstrap-source manager))
         (primary (credential-source-load primary-source)))
    (cond
      (primary
       (credential-manager-accept-account
        manager (credential-manager-validate-credentials manager primary)))
      (t
       (let ((bootstrap
               (and bootstrap-source
                    (credential-source-load bootstrap-source))))
         (if bootstrap
             (credential-manager-import-bootstrap manager bootstrap)
             (error *credentials-unavailable-class*
                    :message
                    (format nil "No ~A OAuth credentials are available; ~A."
                            (credential-manager-provider-label manager)
                            (credential-manager-login-hint manager))
                    :searched-paths
                    (remove nil
                            (list
                             (credential-source-pathname primary-source)
                             (and bootstrap-source
                                  (credential-source-pathname
                                   bootstrap-source)))))))))))


(defun oauth-credentials-refresh-identity-equal-p (left right)
  "Return true when LEFT and RIGHT identify the same refresh-token generation."
  (and (string= (oauth-credentials-access-token left)
                (oauth-credentials-access-token right))
       (equal (oauth-credentials-refresh-token left)
              (oauth-credentials-refresh-token right))))


(defun credential-manager-refresh (manager stale-credentials)
  "Refresh STALE-CREDENTIALS with one in-process exchange per token generation."
  (credential-manager-accept-account manager stale-credentials)
  (labels ((wait-for-generation (generation)
             "Wait for GENERATION and replay its immutable terminal outcome."
             (with-lock-held ((credential-refresh-generation-lock generation))
               (incf (credential-refresh-generation-waiter-count generation))
               (condition-notify
                (credential-refresh-generation-completion generation))
               (unwind-protect
                    (loop until
                          (credential-refresh-generation-completed-p generation)
                          do (condition-wait
                              (credential-refresh-generation-completion generation)
                              (credential-refresh-generation-lock generation)))
                 (decf (credential-refresh-generation-waiter-count generation)))
               (ecase (credential-refresh-generation-outcome-kind generation)
                 (:success
                  (credential-refresh-generation-result generation))
                 (:failure
                  (error (credential-refresh-generation-failure generation)))
                 (:abandoned
                  nil))))

           (finish-generation (generation outcome-kind &key result failure)
             "Publish GENERATION's immutable outcome and release every waiter."
             (sb-sys:without-interrupts
               (with-lock-held ((credential-manager-refresh-lock manager))
                 (when (eq generation
                           (credential-manager--refresh-generation manager))
                   (setf (credential-manager--refresh-generation manager) nil
                         (credential-manager--refresh-in-progress-p manager) nil)
                   (sb-thread:condition-broadcast
                    (credential-manager--refresh-completion manager))))
               (with-lock-held ((credential-refresh-generation-lock generation))
                 (unless (credential-refresh-generation-completed-p generation)
                   (setf (credential-refresh-generation-outcome-kind generation)
                         outcome-kind
                         (credential-refresh-generation-result generation) result
                         (credential-refresh-generation-failure generation) failure
                         (credential-refresh-generation-completed-p generation) t)
                   (sb-thread:condition-broadcast
                    (credential-refresh-generation-completion generation))))))

           (select-action (record-leader)
             "Select a completed credential, waiter result, or leader exchange."
             (with-lock-held ((credential-manager-refresh-lock manager))
               (when (credential-manager--refresh-in-progress-p manager)
                 (return-from select-action
                   (values ':wait nil nil
                           (credential-manager--refresh-generation manager))))
               (let* ((primary-source (credential-manager-primary-source manager))
                      (bootstrap-source (credential-manager-bootstrap-source manager))
                      (bootstrap-pathname
                        (and bootstrap-source
                             (credential-source-pathname bootstrap-source)))
                      (latest (credential-source-load primary-source))
                      (latest-different-p
                        (and latest
                             (not (oauth-credentials-refresh-identity-equal-p
                                   latest stale-credentials))))
                      (credentials
                        (if latest-different-p
                            (credential-manager-accept-account
                             manager
                             (credential-manager-validate-credentials manager latest))
                            stale-credentials))
                      (refresh-token
                        (oauth-credentials-refresh-token credentials)))
                 (when (and bootstrap-pathname
                            (equal (oauth-credentials-source-path credentials)
                                   bootstrap-pathname))
                   (error *token-refresh-failed-class*
                          :message
                          (format nil
                                  "~A bootstrap credentials must not be refreshed through this manager."
                                  (credential-source-label bootstrap-source))
                          :status nil
                          :response nil))
                 (when (and latest-different-p
                            (not (credentials-needs-refresh-p latest)))
                   (return-from select-action
                     (values ':return credentials nil nil)))
                 (unless (non-empty-string-p refresh-token)
                   (error *token-refresh-failed-class*
                          :message (format nil "These credentials cannot refresh; ~A."
                                           (credential-manager-login-hint manager))
                          :status nil
                          :response nil))
                 (incf (credential-manager--refresh-epoch manager))
                 (let ((generation
                         (make-instance
                          'credential-refresh-generation
                          :number (credential-manager--refresh-epoch manager))))
                   (sb-sys:without-interrupts
                     (funcall record-leader generation)
                     (setf (credential-manager--refresh-generation manager) generation
                           (credential-manager--refresh-in-progress-p manager) t))
                   (values ':lead credentials refresh-token generation)))))

           (complete-success (generation refreshed publish-p)
             "Publish REFRESHED and notify waiters for GENERATION."
             (with-lock-held ((credential-manager-refresh-lock manager))
               (bordeaux-threads:with-recursive-lock-held
                   ((credential-manager--account-lock manager))
                 (credential-manager-accept-account manager refreshed)
                 (when publish-p
                   (credential-source-save
                    (credential-manager-primary-source manager) refreshed))))
             (finish-generation generation ':success :result refreshed)
             refreshed))
    (loop
      (let ((leader-generation nil))
        (unwind-protect
             (multiple-value-bind (action credentials refresh-token generation)
                 (select-action
                  (lambda (selected-generation)
                    (setf leader-generation selected-generation)))
               (ecase action
                 (:wait
                  (let ((result (wait-for-generation generation)))
                    (when result
                      (return result))))
                 (:return
                  (return credentials))
                 (:lead
                  (credential-manager--refresh-generation-installed
                   manager generation)
                  (handler-case
                      (return
                        (credential-manager-call-with-refresh-lock
                         manager
                         (lambda ()
                           (multiple-value-bind (refreshed publish-p)
                               (credential-manager--exchange-latest
                                manager credentials refresh-token)
                             (complete-success generation refreshed publish-p)))))
                    (error (condition)
                      (finish-generation
                       generation ':failure :failure condition)
                      (error condition))))))
          (when leader-generation
            (finish-generation leader-generation ':abandoned)))))))


(defun credential-manager--exchange-latest (manager credentials refresh-token)
  "Exchange REFRESH-TOKEN unless the primary source already holds a newer rotation.

The refresh leader calls this under the refresh lock, so a rotation another
process published while this one waited is adopted instead of spending its
predecessor. Return the credentials and whether the caller must publish them."
  (let ((latest (credential-source-load (credential-manager-primary-source manager))))
    (if (and latest
             (not (oauth-credentials-refresh-identity-equal-p latest credentials)))
        (values (credential-manager-accept-account
                 manager (credential-manager-validate-credentials manager latest))
                nil)
        (credential-manager-refresh-exchange manager credentials refresh-token))))


(defun credential-manager-credentials (manager &key force-refresh)
  "Load credentials and refresh them when expired or FORCE-REFRESH is true."
  (let ((credentials (credential-manager-load manager)))
    (if (or force-refresh (credentials-needs-refresh-p credentials))
        (credential-manager-refresh manager credentials)
        credentials)))


(defmethod credential-manager-provider-label ((manager managed-credential-manager))
  "Describe the default credential service."
  (declare (ignore manager))
  "OAuth")


(defmethod credential-manager-login-hint ((manager managed-credential-manager))
  "Describe the default reauthentication action."
  (declare (ignore manager))
  "authenticate again")


(defun credential-manager-newer-rotation (manager attempted-refresh-token)
  "Reread and validate a stored rotation replacing ATTEMPTED-REFRESH-TOKEN."
  (let ((latest (credential-source-load (credential-manager-primary-source manager))))
    (when (and latest
               (non-empty-string-p (oauth-credentials-refresh-token latest))
               (not (string= (oauth-credentials-refresh-token latest)
                             attempted-refresh-token)))
      (credential-manager-accept-account
       manager (credential-manager-validate-credentials manager latest)))))


(defun call-with-credentials (manager function &key force-refresh)
  "Call FUNCTION with freshly loaded credentials inside the host's secret region."
  (funcall *secret-region-function*
           (lambda ()
             (funcall function
                      (credential-manager-credentials manager
                                                      :force-refresh force-refresh)))))


(defmacro with-credentials ((variable manager &key force-refresh) &body body)
  "Bind VARIABLE to fresh credentials for BODY within the host's secret region."
  `(call-with-credentials ,manager (lambda (,variable) ,@body)
                          :force-refresh ,force-refresh))
