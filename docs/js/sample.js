/* Extracto representativo de php.ini-production (PHP 8.x) para probar la herramienta. */
window.PHP_INI_SAMPLE = `[PHP]
;;;;;;;;;;;;;;;;;;;
; About php.ini   ;
;;;;;;;;;;;;;;;;;;;
; Extracto de php.ini-production para pruebas del analizador PHP2Shell.

engine = On
short_open_tag = Off
precision = 14
output_buffering = 4096
zlib.output_compression = Off
implicit_flush = Off
serialize_precision = -1
disable_functions =
zend.enable_gc = On

; Decides whether PHP may expose the fact that it is installed on the server
expose_php = On

max_execution_time = 30
max_input_time = 60
;max_input_nesting_level = 64
; How many GET/POST/COOKIE input variables may be accepted
;max_input_vars = 1000

; Maximum amount of memory a script may consume
; https://php.net/memory-limit
memory_limit = 128M

error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
display_errors = Off
display_startup_errors = Off
log_errors = On

; Maximum size of POST data that PHP will accept.
; https://php.net/post-max-size
post_max_size = 64M

[Data Handling]
variables_order = "GPS"
request_order = "GP"
register_argc_argv = Off
auto_globals_jit = On

; Whether to allow HTTP file uploads.
; https://php.net/file-uploads
file_uploads = On

; Maximum allowed size for uploaded files.
; https://php.net/upload-max-filesize
upload_max_filesize = 32M

; Maximum number of files that can be uploaded via a single request
max_file_uploads = 50

[Session]
session.save_handler = files
session.use_strict_mode = 0
session.use_cookies = 1
session.cookie_httponly =
session.gc_maxlifetime = 1440

; Enable upload progress tracking in $_SESSION
; https://php.net/session.upload-progress.enabled
;session.upload_progress.enabled = On

; Cleanup the progress information as soon as all POST data has been read
;session.upload_progress.cleanup = On
;session.upload_progress.prefix = "upload_progress_"
;session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"

[opcache]
opcache.enable=1
opcache.memory_consumption=128
`;
