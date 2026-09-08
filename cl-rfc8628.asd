(asdf:defsystem #:cl-rfc8628
  :description "The OAuth 2.0 device authorization grant as a CLOS protocol."
  :author "Lambda Symbolics OÜ"
  :license "COLL-Attribution"
  :version "0.1.0"
  :serial t
  :depends-on (#:bordeaux-threads
               #:cl-base64
               #:dexador
               #:quri
               #:yason)
  :components ((:module "src"
                :serial t
                :components ((:file "package")
                             (:file "support")
                             (:file "store")
                             (:file "client")
                             (:file "manager")
                             (:file "rfc8628"))))
  :in-order-to ((asdf:test-op (asdf:test-op #:cl-rfc8628/tests))))

(asdf:defsystem #:cl-rfc8628/tests
  :description "Tests for cl-rfc8628."
  :depends-on (#:cl-rfc8628)
  :serial t
  :components ((:module "tests"
                :serial t
                :components ((:file "tests")
                             (:file "manager"))))
  :perform (asdf:test-op (operation component)
             (declare (ignore operation component))
             (uiop:symbol-call '#:cl-rfc8628/tests '#:run-tests)))
