(in-package #:cl-rfc8628)


(defclass oauth-test-memory-credential-source (cl-rfc8628/tests::test-credential-source)
  ((credentials
    :initarg :credentials
    :accessor oauth-test-memory-source-credentials
    :type oauth-credentials
    :documentation "The in-memory credentials returned by this test source.")
   (save-count
    :initform 0
    :accessor oauth-test-memory-source-save-count
    :type (integer 0)
    :documentation "The number of credentials published to this test source."))
  (:documentation "An in-memory credential source for refresh concurrency tests."))


(defmethod credential-source-load ((source oauth-test-memory-credential-source))
  "Return SOURCE's current in-memory credentials."
  (oauth-test-memory-source-credentials source))


(defmethod credential-source-save
    ((source oauth-test-memory-credential-source)
     (credentials oauth-credentials))
  "Publish CREDENTIALS to SOURCE's in-memory store."
  (incf (oauth-test-memory-source-save-count source))
  (setf (oauth-test-memory-source-credentials source) credentials)
  nil)


(defclass oauth-test-refresh-manager (managed-credential-manager)
  ((gate-lock
    :initform (make-lock "OAuth refresh test gate")
    :reader oauth-test-refresh-manager-gate-lock
    :documentation "The lock protecting this test manager's exchange gate.")
   (gate-condition
    :initform (make-condition-variable :name "OAuth refresh test gate")
    :reader oauth-test-refresh-manager-gate-condition
    :documentation "The condition variable controlling the test exchange.")
   (released-count
    :initform 0
    :accessor oauth-test-refresh-manager-released-count
    :type (integer 0)
    :documentation "The number of synthetic exchanges allowed to leave the gate.")
   (exchange-count
    :initform 0
    :accessor oauth-test-refresh-manager-exchange-count
    :type (integer 0)
    :documentation "The number of synthetic refresh exchanges that reached the gate.")
   (outcomes
    :initarg :outcomes
    :initform '(:success)
    :accessor oauth-test-refresh-manager-outcomes
    :type list
    :documentation "The ordered synthetic outcomes for successive exchanges.")
   (refreshed-credentials
    :initarg :refreshed-credentials
    :reader oauth-test-refresh-manager-refreshed-credentials
    :type oauth-credentials
    :documentation "The credentials returned by a successful synthetic exchange."))
  (:documentation "A fully gated refresh manager used for deterministic concurrency tests."))


(defmethod credential-manager-refresh-exchange
    ((manager oauth-test-refresh-manager)
     (credentials oauth-credentials)
     (refresh-token string))
  "Wait at MANAGER's numbered gate, then perform its configured synthetic outcome."
  (declare (ignore credentials refresh-token))
  (let (number outcome)
    (with-lock-held ((oauth-test-refresh-manager-gate-lock manager))
      (setf number (incf (oauth-test-refresh-manager-exchange-count manager)))
      (sb-thread:condition-broadcast
       (oauth-test-refresh-manager-gate-condition manager))
      (loop while (> number (oauth-test-refresh-manager-released-count manager))
            do (condition-wait
                (oauth-test-refresh-manager-gate-condition manager)
                (oauth-test-refresh-manager-gate-lock manager)))
      (setf outcome
            (or (nth (1- number) (oauth-test-refresh-manager-outcomes manager))
                ':success)))
    (ecase outcome
      (:success
       (values (oauth-test-refresh-manager-refreshed-credentials manager) t))
      (:success-without-publication
       (values (oauth-test-refresh-manager-refreshed-credentials manager) nil))
      (:failure
       (error 'token-refresh-failed
              :message "Synthetic refresh failure."
              :status nil
              :response nil))
      (:throw
       (throw 'oauth-test-refresh-abort ':abandoned)))))


(defclass oauth-test-install-gated-refresh-manager
    (oauth-test-refresh-manager)
  ((install-count
    :initform 0
    :accessor oauth-test-refresh-manager-install-count
    :type (integer 0)
    :documentation "The number of leader generations observed before exchange.")
   (install-blocked-p
    :initform t
    :accessor oauth-test-refresh-manager-install-blocked-p
    :type boolean
    :documentation "Whether leader installation waits at the deterministic test gate."))
  (:documentation "A refresh manager that can be interrupted after leader publication."))


(defmethod credential-manager--refresh-generation-installed
    ((manager oauth-test-install-gated-refresh-manager)
     (generation credential-refresh-generation))
  "Block after GENERATION is externally visible and before its exchange begins."
  (declare (ignore generation))
  (with-lock-held ((oauth-test-refresh-manager-gate-lock manager))
    (incf (oauth-test-refresh-manager-install-count manager))
    (sb-thread:condition-broadcast
     (oauth-test-refresh-manager-gate-condition manager))
    (loop while (oauth-test-refresh-manager-install-blocked-p manager)
          do (condition-wait
              (oauth-test-refresh-manager-gate-condition manager)
              (oauth-test-refresh-manager-gate-lock manager))))
  nil)


(defun oauth-test--refresh-fixture (&key (outcomes '(:success)))
  "Return a gated manager, memory source, and stale/fresh credentials."
  (let* ((pathname #P"/tmp/chatgpt-refresh-single-flight.sexp")
         (stale
           (make-instance 'oauth-credentials
                          :access-token "stale-access"
                          :refresh-token "rotating-refresh"
                          :id-token nil
                          :account-id "account-refresh"
                          :expires-at nil
                          :source-path pathname))
         (fresh
           (make-instance 'oauth-credentials
                          :access-token "fresh-access"
                          :refresh-token "rotated-refresh"
                          :id-token nil
                          :account-id "account-refresh"
                          :expires-at (+ (get-universal-time) 3600)
                          :source-path pathname))
         (source
           (make-instance 'oauth-test-memory-credential-source
                          :pathname pathname
                          :credentials stale))
         (manager
           (make-instance 'oauth-test-refresh-manager
                          :primary-source source
                          :outcomes outcomes
                          :refreshed-credentials fresh)))
    (values manager source stale fresh)))


(defun oauth-test--wait-for-exchange-count (manager count)
  "Wait at most five seconds for MANAGER to begin COUNT synthetic exchanges."
  (sb-sys:with-deadline (:seconds 5)
    (with-lock-held ((oauth-test-refresh-manager-gate-lock manager))
      (loop while (< (oauth-test-refresh-manager-exchange-count manager) count)
            do (condition-wait
                (oauth-test-refresh-manager-gate-condition manager)
                (oauth-test-refresh-manager-gate-lock manager)))))
  nil)


(defun oauth-test--release-refresh-exchange (manager)
  "Release the next numbered synthetic exchange for MANAGER."
  (with-lock-held ((oauth-test-refresh-manager-gate-lock manager))
    (incf (oauth-test-refresh-manager-released-count manager))
    (sb-thread:condition-broadcast
     (oauth-test-refresh-manager-gate-condition manager)))
  nil)


(defun oauth-test--current-refresh-generation (manager)
  "Return MANAGER's active refresh generation under its state lock."
  (with-lock-held ((credential-manager-refresh-lock manager))
    (or (credential-manager--refresh-generation manager)
        (error "The test manager has no active refresh generation."))))


(defun oauth-test--wait-for-generation-waiter (generation)
  "Wait at most five seconds until GENERATION has an observable waiter."
  (sb-sys:with-deadline (:seconds 5)
    (with-lock-held ((credential-refresh-generation-lock generation))
      (loop until (plusp (credential-refresh-generation-waiter-count generation))
            do (condition-wait
                (credential-refresh-generation-completion generation)
                (credential-refresh-generation-lock generation)))))
  nil)


(defun oauth-test--wait-for-manager-idle (manager)
  "Wait at most five seconds until MANAGER exposes no active refresh generation."
  (sb-sys:with-deadline (:seconds 5)
    (with-lock-held ((credential-manager-refresh-lock manager))
      (loop while (credential-manager--refresh-generation manager)
            do (condition-wait
                (credential-manager--refresh-completion manager)
                (credential-manager-refresh-lock manager)))))
  nil)


(defun oauth-test--join-thread (thread)
  "Join THREAD within five seconds and return its primary value."
  (let ((result (sb-thread:join-thread thread :timeout 5 :default ':timed-out)))
    (cl-rfc8628/tests::check (not (eq result ':timed-out))
                 "the gated refresh test thread terminates within its bound")
    result))


(defun oauth-test--single-flight-refresh ()
  "Test deterministic refresh success, failure replay, and non-local cleanup."
  (multiple-value-bind (manager source stale fresh)
      (oauth-test--refresh-fixture)
    (let ((first-result nil)
          (second-result nil))
      (let ((first-thread
              (bordeaux-threads:make-thread
               (lambda ()
                 (setf first-result (credential-manager-refresh manager stale)))
               :name "OAuth refresh leader")))
        (oauth-test--wait-for-exchange-count manager 1)
        (let ((generation (oauth-test--current-refresh-generation manager)))
          (let ((acquired-p
                  (bordeaux-threads:acquire-lock
                   (credential-manager-refresh-lock manager)
                   nil)))
            (cl-rfc8628/tests::check acquired-p
                         "a blocked refresh exchange does not hold the manager lock")
            (when acquired-p
              (bordeaux-threads:release-lock
               (credential-manager-refresh-lock manager))))
          (let ((second-thread
                  (bordeaux-threads:make-thread
                   (lambda ()
                     (setf second-result
                           (credential-manager-refresh manager stale)))
                   :name "OAuth refresh waiter")))
            (oauth-test--wait-for-generation-waiter generation)
            (oauth-test--release-refresh-exchange manager)
            (oauth-test--join-thread first-thread)
            (oauth-test--join-thread second-thread)
            (cl-rfc8628/tests::check
             (and (eq first-result fresh)
                  (eq second-result fresh)
                  (= (oauth-test-refresh-manager-exchange-count manager) 1)
                  (= (oauth-test-memory-source-save-count source) 1))
             "concurrent refresh success performs one exchange and one publication"))))))
  (multiple-value-bind (manager source stale fresh)
      (oauth-test--refresh-fixture :outcomes '(:failure :success))
    (declare (ignore fresh))
    (flet ((attempt-refresh ()
             (handler-case
                 (credential-manager-refresh manager stale)
               (token-refresh-failed (condition)
                 condition))))
      (let ((first-result nil)
            (second-result nil))
        (let ((first-thread
                (bordeaux-threads:make-thread
                 (lambda () (setf first-result (attempt-refresh)))
                 :name "OAuth failed refresh leader")))
          (oauth-test--wait-for-exchange-count manager 1)
          (let* ((generation (oauth-test--current-refresh-generation manager))
                 (second-thread
                   (bordeaux-threads:make-thread
                    (lambda () (setf second-result (attempt-refresh)))
                    :name "OAuth failed refresh waiter")))
            (oauth-test--wait-for-generation-waiter generation)
            (oauth-test--release-refresh-exchange manager)
            (oauth-test--join-thread first-thread)
            (oauth-test--join-thread second-thread)
            (cl-rfc8628/tests::check
             (and (typep first-result 'token-refresh-failed)
                  (eq first-result second-result)
                  (= (oauth-test-refresh-manager-exchange-count manager) 1)
                  (zerop (oauth-test-memory-source-save-count source)))
             "concurrent refresh failure is replayed from one immutable outcome")
            (oauth-test--release-refresh-exchange manager)
            (let ((retry (credential-manager-refresh manager stale)))
              (cl-rfc8628/tests::check
               (and (string= (oauth-credentials-access-token retry) "fresh-access")
                    (= (oauth-test-refresh-manager-exchange-count manager) 2)
                    (= (oauth-test-memory-source-save-count source) 1))
               "a later refresh may proceed after a shared failure")))))))
  (multiple-value-bind (manager source stale fresh)
      (oauth-test--refresh-fixture :outcomes '(:failure :success))
    (declare (ignore source))
    (flet ((attempt-refresh ()
             (handler-case
                 (credential-manager-refresh manager stale)
               (token-refresh-failed (condition)
                 condition))))
      (let ((leader-result nil)
            (waiter-result nil)
            (next-result nil))
        (let ((leader-thread
                (bordeaux-threads:make-thread
                 (lambda () (setf leader-result (attempt-refresh)))
                 :name "OAuth epoch N leader")))
          (oauth-test--wait-for-exchange-count manager 1)
          (let* ((generation (oauth-test--current-refresh-generation manager))
                 (waiter-thread
                   (bordeaux-threads:make-thread
                    (lambda () (setf waiter-result (attempt-refresh)))
                    :name "OAuth epoch N waiter")))
            (oauth-test--wait-for-generation-waiter generation)
            (let ((next-thread nil))
              (with-lock-held ((credential-refresh-generation-lock generation))
                (oauth-test--release-refresh-exchange manager)
                (oauth-test--wait-for-manager-idle manager)
                (setf next-thread
                      (bordeaux-threads:make-thread
                       (lambda ()
                         (setf next-result
                               (credential-manager-refresh manager stale)))
                       :name "OAuth epoch N+1 leader"))
                (oauth-test--wait-for-exchange-count manager 2))
              (oauth-test--join-thread leader-thread)
              (oauth-test--join-thread waiter-thread)
              (cl-rfc8628/tests::check
               (and (typep leader-result 'token-refresh-failed)
                    (eq leader-result waiter-result))
               "epoch N failure survives epoch N+1 starting before its waiter resumes")
              (oauth-test--release-refresh-exchange manager)
              (oauth-test--join-thread next-thread)
              (cl-rfc8628/tests::check (eq next-result fresh)
                           "epoch N+1 completes independently of epoch N's outcome")))))))
  (multiple-value-bind (manager source stale fresh)
      (oauth-test--refresh-fixture
       :outcomes '(:success-without-publication :failure))
    (flet ((attempt-refresh ()
             (handler-case
                 (credential-manager-refresh manager stale)
               (token-refresh-failed (condition)
                 condition))))
      (let ((leader-result nil)
            (waiter-result nil)
            (next-result nil))
        (let ((leader-thread
                (bordeaux-threads:make-thread
                 (lambda () (setf leader-result (attempt-refresh)))
                 :name "OAuth successful epoch N leader")))
          (oauth-test--wait-for-exchange-count manager 1)
          (let* ((generation (oauth-test--current-refresh-generation manager))
                 (waiter-thread
                   (bordeaux-threads:make-thread
                    (lambda () (setf waiter-result (attempt-refresh)))
                    :name "OAuth successful epoch N waiter")))
            (oauth-test--wait-for-generation-waiter generation)
            (let ((next-thread nil))
              (with-lock-held ((credential-refresh-generation-lock generation))
                (oauth-test--release-refresh-exchange manager)
                (oauth-test--wait-for-manager-idle manager)
                (setf next-thread
                      (bordeaux-threads:make-thread
                       (lambda () (setf next-result (attempt-refresh)))
                       :name "OAuth failing epoch N+1 leader"))
                (oauth-test--wait-for-exchange-count manager 2))
              (oauth-test--join-thread leader-thread)
              (oauth-test--join-thread waiter-thread)
              (cl-rfc8628/tests::check
               (and (eq leader-result fresh)
                    (eq waiter-result fresh)
                    (zerop (oauth-test-memory-source-save-count source)))
               "epoch N success survives epoch N+1 starting before its waiter resumes")
              (oauth-test--release-refresh-exchange manager)
              (oauth-test--join-thread next-thread)
              (cl-rfc8628/tests::check
               (typep next-result 'token-refresh-failed)
               "epoch N+1 failure remains independent of epoch N's success")))))))
  (multiple-value-bind (manager source stale fresh)
      (oauth-test--refresh-fixture :outcomes '(:throw :success))
    (let ((leader-result nil)
          (waiter-result nil))
      (let ((leader-thread
              (bordeaux-threads:make-thread
               (lambda ()
                 (setf leader-result
                       (catch 'oauth-test-refresh-abort
                         (credential-manager-refresh manager stale))))
               :name "OAuth abandoned refresh leader")))
        (oauth-test--wait-for-exchange-count manager 1)
        (let* ((generation (oauth-test--current-refresh-generation manager))
               (waiter-thread
                 (bordeaux-threads:make-thread
                  (lambda ()
                    (setf waiter-result
                          (credential-manager-refresh manager stale)))
                  :name "OAuth abandoned refresh waiter")))
          (oauth-test--wait-for-generation-waiter generation)
          (oauth-test--release-refresh-exchange manager)
          (oauth-test--wait-for-exchange-count manager 2)
          (oauth-test--release-refresh-exchange manager)
          (oauth-test--join-thread leader-thread)
          (oauth-test--join-thread waiter-thread)
          (cl-rfc8628/tests::check
           (and (eq leader-result ':abandoned)
                (eq waiter-result fresh)
                (= (oauth-test-refresh-manager-exchange-count manager) 2)
                (= (oauth-test-memory-source-save-count source) 1)
                (not (credential-manager--refresh-in-progress-p manager)))
           "a non-local leader exit broadcasts cleanup and leaves retryable state")))))
  nil)


(defun oauth-test--leader-install-interruption ()
  "Interrupt a published refresh leader before exchange and prove cleanup wakes callers."
  (multiple-value-bind (base-manager source stale fresh)
      (oauth-test--refresh-fixture)
    (declare (ignore base-manager))
    (let* ((manager
             (make-instance
              'oauth-test-install-gated-refresh-manager
              :primary-source source
              :refreshed-credentials fresh))
           (leader-result nil)
           (waiter-result nil)
           (leader-thread
             (bordeaux-threads:make-thread
              (lambda ()
                (setf leader-result
                      (catch 'oauth-test-refresh-install-abort
                        (credential-manager-refresh manager stale))))
              :name "OAuth pre-exchange refresh leader")))
      (sb-sys:with-deadline (:seconds 5)
        (with-lock-held ((oauth-test-refresh-manager-gate-lock manager))
          (loop until (= (oauth-test-refresh-manager-install-count manager) 1)
                do (condition-wait
                    (oauth-test-refresh-manager-gate-condition manager)
                    (oauth-test-refresh-manager-gate-lock manager)))))
      (let* ((generation (oauth-test--current-refresh-generation manager))
             (waiter-thread
               (bordeaux-threads:make-thread
                (lambda ()
                  (setf waiter-result
                        (credential-manager-refresh manager stale)))
                :name "OAuth pre-exchange refresh waiter")))
        (oauth-test--wait-for-generation-waiter generation)
        (sb-thread:interrupt-thread
         leader-thread
         (lambda ()
           (throw 'oauth-test-refresh-install-abort ':interrupted)))
        (cl-rfc8628/tests::check (eq (oauth-test--join-thread leader-thread) ':interrupted)
                     "the refresh leader is interrupted before exchange")
        (sb-sys:with-deadline (:seconds 5)
          (with-lock-held ((oauth-test-refresh-manager-gate-lock manager))
            (loop until (= (oauth-test-refresh-manager-install-count manager) 2)
                  do (condition-wait
                      (oauth-test-refresh-manager-gate-condition manager)
                      (oauth-test-refresh-manager-gate-lock manager)))
            (setf (oauth-test-refresh-manager-install-blocked-p manager) nil)
            (sb-thread:condition-broadcast
             (oauth-test-refresh-manager-gate-condition manager))))
        (oauth-test--wait-for-exchange-count manager 1)
        (oauth-test--release-refresh-exchange manager)
        (oauth-test--join-thread waiter-thread)
        (oauth-test--wait-for-manager-idle manager)
        (cl-rfc8628/tests::check
         (and (eq waiter-result fresh)
              (eq (credential-manager-refresh manager stale) fresh)
              (= (oauth-test-refresh-manager-exchange-count manager) 1)
              (= (oauth-test-memory-source-save-count source) 1)
              (not (credential-manager--refresh-in-progress-p manager)))
         "leader cleanup wakes waiters and leaves later refresh calls usable"))))
  nil)


(defun oauth-test--rotated-refresh-token-reconciliation ()
  "Test source reconciliation notices refresh-token rotation without access rotation."
  (multiple-value-bind (manager source stale fresh)
      (oauth-test--refresh-fixture)
    (declare (ignore fresh))
    (let ((rotated
            (make-instance 'oauth-credentials
                           :access-token (oauth-credentials-access-token stale)
                           :refresh-token "externally-rotated-refresh"
                           :id-token nil
                           :account-id (oauth-credentials-account-id stale)
                           :expires-at (+ (get-universal-time) 3600)
                           :source-path (oauth-credentials-source-path stale))))
      (setf (oauth-test-memory-source-credentials source) rotated)
      (cl-rfc8628/tests::check
       (and (eq (credential-manager-refresh manager stale) rotated)
            (zerop (oauth-test-refresh-manager-exchange-count manager)))
       "the stale-source recheck adopts a refresh-token-only rotation")))
  (multiple-value-bind (manager source credentials fresh)
      (oauth-test--refresh-fixture)
    (declare (ignore fresh))
    (let ((access-only
            (make-instance 'oauth-credentials
                           :access-token "externally-rotated-access"
                           :refresh-token
                           (oauth-credentials-refresh-token credentials)
                           :id-token nil
                           :account-id (oauth-credentials-account-id credentials)
                           :expires-at (+ (get-universal-time) 3600)
                           :source-path (oauth-credentials-source-path credentials))))
      (setf (oauth-test-memory-source-credentials source) access-only)
      (cl-rfc8628/tests::check
       (null (credential-manager-newer-rotation
              manager
              (oauth-credentials-refresh-token credentials)))
       "refresh_token_reused rejects an access-only source rotation"))
    (let ((rotated
            (make-instance 'oauth-credentials
                           :access-token (oauth-credentials-access-token credentials)
                           :refresh-token "reused-recovery-refresh"
                           :id-token nil
                           :account-id (oauth-credentials-account-id credentials)
                           :expires-at (+ (get-universal-time) 3600)
                           :source-path (oauth-credentials-source-path credentials))))
      (setf (oauth-test-memory-source-credentials source) rotated)
      (cl-rfc8628/tests::check
       (eq (credential-manager-newer-rotation
            manager
            (oauth-credentials-refresh-token credentials))
           rotated)
       "refresh_token_reused adopts a refresh-token-only source rotation")))
  nil)


(defclass oauth-test-failing-source (oauth-test-memory-credential-source)
  ((failure :initarg :failure :reader oauth-test-source-failure))
  (:documentation "A source that rejects publication with one shared condition."))


(defmethod credential-source-save ((source oauth-test-failing-source) credentials)
  "Reject publication without changing the in-memory source."
  (declare (ignore credentials))
  (error (oauth-test-source-failure source)))


(defun oauth-test--publication-failure ()
  "Share a failed store publication and retire the generation."
  (multiple-value-bind (manager source stale fresh) (oauth-test--refresh-fixture)
    (declare (ignore fresh))
    (let* ((failure (make-condition 'token-refresh-failed :message "Store unavailable."))
           (leader-result nil)
           (waiter-result nil))
      (change-class source 'oauth-test-failing-source :failure failure)
      (let ((leader (bordeaux-threads:make-thread
                     (lambda ()
                       (setf leader-result
                             (handler-case (credential-manager-refresh manager stale)
                               (token-refresh-failed (condition) condition)))))))
        (oauth-test--wait-for-exchange-count manager 1)
        (let* ((generation (oauth-test--current-refresh-generation manager))
               (waiter (bordeaux-threads:make-thread
                        (lambda ()
                          (setf waiter-result
                                (handler-case (credential-manager-refresh manager stale)
                                  (token-refresh-failed (condition) condition)))))))
          (oauth-test--wait-for-generation-waiter generation)
          (oauth-test--release-refresh-exchange manager)
          (oauth-test--join-thread leader)
          (oauth-test--join-thread waiter)
          (cl-rfc8628/tests::check
           (and (eq failure leader-result) (eq failure waiter-result)
                (eq stale (credential-source-load source))
                (not (credential-manager--refresh-in-progress-p manager)))
           "publication failure is shared without publishing credentials"))))))


(defun oauth-test--source-and-scope ()
  "Test bounded imports, continuity, fresh reads and secret-scope unwinding."
  (multiple-value-bind (unused source stale fresh) (oauth-test--refresh-fixture)
    (declare (ignore unused))
    (let* ((cl-rfc8628/tests::*saved-credentials* nil)
           (primary (make-instance 'cl-rfc8628/tests::test-credential-source
                                   :pathname #P"/test/primary.sexp"))
           (manager (make-instance 'managed-credential-manager
                                   :primary-source primary :bootstrap-source source)))
      (setf (oauth-test-memory-source-credentials source) fresh)
      (let ((imported (credential-manager-load manager)))
        (cl-rfc8628/tests::check
         (and (string= (oauth-credentials-access-token imported)
                       (oauth-credentials-access-token fresh))
              (null (oauth-credentials-refresh-token imported))
              (null (oauth-credentials-id-token imported))
              (equal (oauth-credentials-source-path imported) #P"/test/primary.sexp")
              (zerop (oauth-test-memory-source-save-count source)))
         "bootstrap import publishes bounded access credentials only")
        (setf cl-rfc8628/tests::*saved-credentials* fresh)
        (cl-rfc8628/tests::check
         (eq fresh (credential-manager-import-bootstrap manager stale))
         "a fresh primary writer takes precedence over an old bootstrap observation"))
      (let ((other (make-instance 'oauth-credentials
                                  :access-token "other-access" :refresh-token "other-refresh"
                                  :account-id "other-account" :expires-at nil
                                  :source-path #P"/test/primary.sexp")))
        (cl-rfc8628/tests::check
         (handler-case (progn (credential-manager-accept-account manager other) nil)
           (credential-error () t))
         "account changes require explicit authorization")
        (credential-manager-accept-account manager other :allow-change t)
        (cl-rfc8628/tests::check
         (string= "other-account" (credential-manager-account-id manager))
         "explicit authorization repins the account")
        (credential-manager-accept-account manager fresh :allow-change t))
      (let ((entered nil) (left nil) (active nil))
        (let ((*secret-region-function*
                (lambda (function)
                  (setf entered t active t)
                  (unwind-protect (funcall function)
                    (setf active nil left t)))))
          (cl-rfc8628/tests::check
           (equal '("result" 42)
                  (multiple-value-list
                   (call-with-credentials manager
                     (lambda (credentials)
                       (cl-rfc8628/tests::check (and active (eq credentials fresh))
                                               "credential callbacks see fresh scoped values")
                       (values "result" 42)))))
           "credential callbacks preserve multiple values")
          (catch 'scope-exit
            (call-with-credentials manager (lambda (credentials)
                                             (declare (ignore credentials))
                                             (throw 'scope-exit t))))
          (cl-rfc8628/tests::check (and entered left (not active))
                                  "secret scope unwinds after nonlocal exits")))
      (setf cl-rfc8628/tests::*saved-credentials* nil
            (oauth-test-memory-source-credentials source)
            (make-instance 'oauth-credentials
                           :access-token "expired-access" :refresh-token nil
                           :account-id (oauth-credentials-account-id fresh)
                           :expires-at (1- (get-universal-time))
                           :source-path (credential-source-pathname source)))
      (cl-rfc8628/tests::check
       (handler-case (progn (credential-manager-load manager) nil)
         (credentials-unavailable () t))
       "expired bootstrap credentials cannot be imported"))))


(defun oauth-test--static-credentials ()
  "Test environment credential sources and the static credential manager."
  (let* ((variable "CL_RFC8628_STATIC_TEST_KEY")
         (environment (make-instance 'environment-credential-source
                                     :environment-variable variable
                                     :account-id "static-test"
                                     :pathname #p"/tmp/static-test.sexp"))
         (stored (make-instance 'oauth-credentials :access-token "stored-key"
                                                   :account-id "static-test"))
         (primary (make-instance 'oauth-test-memory-credential-source
                                 :pathname #p"/tmp/stored-key.sexp"
                                 :credentials stored))
         (manager (make-instance 'static-credential-manager
                                 :primary-source primary
                                 :bootstrap-source environment)))
    (unwind-protect
         (progn
           (setf (uiop:getenv variable) "  ")
           (cl-rfc8628/tests::check (null (credential-source-load environment))
                                    "a blank environment variable holds no credential")
           (cl-rfc8628/tests::check
            (string= (oauth-credentials-access-token (credential-manager-load manager))
                     "stored-key")
            "without the environment value the stored key loads")
           (setf (uiop:getenv variable) "environment-key")
           (let ((loaded (credential-source-load environment)))
             (cl-rfc8628/tests::check
              (and (string= (oauth-credentials-access-token loaded) "environment-key")
                   (string= (oauth-credentials-account-id loaded) "static-test")
                   (equal (oauth-credentials-source-path loaded) #p"/tmp/static-test.sexp")
                   (search variable (credential-source-label environment)))
              "the environment source loads its key under the pinned account"))
           (cl-rfc8628/tests::check
            (string= (oauth-credentials-access-token (credential-manager-load manager))
                     "environment-key")
            "the environment key takes precedence over the stored key")
           (cl-rfc8628/tests::check
            (and (not (credential-manager-refreshable-p manager))
                 (string= (credential-manager-credential-description manager) "API key"))
            "static credentials never refresh and are described as API keys")
           (cl-rfc8628/tests::check
            (handler-case (progn (credential-source-save environment stored) nil)
              (credential-error () t))
            "the environment source is read-only")
           (setf (uiop:getenv variable) ""
                 (oauth-test-memory-source-credentials primary) nil)
           (cl-rfc8628/tests::check
            (handler-case (progn (credential-manager-load manager) nil)
              (credentials-unavailable (condition)
                (and (search "API key is available" (credential-error-message condition))
                     (equal (credentials-unavailable-searched-paths condition)
                            (list #p"/tmp/stored-key.sexp")))))
            "with neither key the manager reports where it searched"))
      (setf (uiop:getenv variable) ""))))

(defun run-manager-tests ()
  "Run the managed credential lifecycle tests."
  (oauth-test--static-credentials)
  (oauth-test--single-flight-refresh)
  (oauth-test--leader-install-interruption)
  (oauth-test--publication-failure)
  (oauth-test--source-and-scope)
  (oauth-test--rotated-refresh-token-reconciliation))
