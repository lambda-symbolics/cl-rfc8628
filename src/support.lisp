(in-package #:cl-rfc8628)

;;;; -- Types --

(deftype option (type)
  "Either NIL or a value of TYPE."
  `(or null ,type))

(deftype non-empty-string ()
  "A string containing at least one character."
  '(and string (not (string 0))))

(deftype timestamp ()
  "A Common Lisp universal time."
  '(integer 0))

(deftype json-object ()
  "A decoded JSON object."
  'hash-table)

(defun non-empty-string-p (value)
  "Return true when VALUE is a string with at least one character."
  (and (stringp value) (plusp (length value)) t))


;;;; -- JSON --

(defun json-object (&rest properties)
  "Return a JSON object holding alternating key and value PROPERTIES."
  (let ((object (make-hash-table :test #'equal)))
    (loop for (key value) on properties by #'cddr
          do (setf (gethash key object) value))
    object))

(defun json-object-p (value)
  "Return true when VALUE is a decoded JSON object."
  (hash-table-p value))

(defun json-array-p (value)
  "Return true when VALUE is a decoded JSON array."
  (and (vectorp value) (not (stringp value))))

(defun json-get (object key)
  "Return KEY's value in JSON OBJECT, or NIL when it is absent."
  (and (hash-table-p object)
       (values (gethash key object))))

(defun json-encode (value)
  "Encode VALUE as compact JSON text."
  (with-output-to-string (stream)
    (yason:encode value stream)))

(defun json-decode (text)
  "Decode JSON TEXT with objects as EQUAL hash tables."
  (yason:parse text
               :object-as ':hash-table
               :json-arrays-as-vectors t
               :json-booleans-as-symbols nil
               :json-nulls-as-keyword nil))


;;;; -- Base64 and Epochs --

(defun padded-base64url (source)
  "Return SOURCE padded to a complete Base64 quartet."
  (let ((missing (mod (- 4 (mod (length source) 4)) 4)))
    (concatenate 'string source (make-string missing :initial-element #\.))))

(defparameter *unix-epoch-universal-time* 2208988800
  "The Common Lisp universal time corresponding to the Unix epoch.")

(defun unix-time->universal-time (unix-time)
  "Convert integer UNIX-TIME seconds to Common Lisp universal time."
  (+ unix-time *unix-epoch-universal-time*))


;;;; -- Exact Redaction --

(defun redact-exact-string-value (source secret marker)
  "Replace every exact SECRET occurrence in SOURCE with MARKER.

Returns SOURCE itself, not a copy, when SECRET is empty or absent."
  (if (or (zerop (length secret))
          (null (search secret source)))
      source
      (with-output-to-string (stream)
        (loop with start = 0
              for position = (search secret source :start2 start)
              do
                 (write-string source stream :start start :end position)
                 (if position
                     (progn
                       (write-string marker stream)
                       (setf start (+ position (length secret))))
                     (return))))))

(defun redact-exact-string-values (source secrets marker)
  "Replace exact SECRETS in SOURCE with MARKER."
  (reduce
   (lambda (current secret)
     (redact-exact-string-value current secret marker))
   (remove-if-not #'non-empty-string-p secrets)
   :initial-value source))

(defun safe-redaction-marker (preferred secrets)
  "Return a marker that cannot contain or form any exact nonempty SECRET."
  (let* ((nonempty-secrets
           (remove-if-not #'non-empty-string-p secrets))
         (sentinel
           (loop for code from #x2588 below char-code-limit
                 for character = (code-char code)
                 when (and
                       character
                       (notany
                        (lambda (secret)
                          (find character secret :test #'char=))
                        nonempty-secrets))
                   return character)))
    (unless sentinel
      (error "No credential-safe redaction marker is available."))
    (if (notany (lambda (secret)
                  (search secret preferred))
                nonempty-secrets)
        (format nil "~C~A~C" sentinel preferred sentinel)
        (string sentinel))))
