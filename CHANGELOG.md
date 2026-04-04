## UPCOMING RELEASE

- CHANGELOG.md: add changelog since 20251001
- main_tlswrapper.c: split plaintext (STARTTLS) phase and TLS phase into separate functions with dedicated buffers
- main_tlswrapper.c: move delayed-encryption buffer management from tls_engine.c into main_tlswrapper.c
- main_tlswrapper.c: abstract TLS API, remove direct BearSSL references
- main_tlswrapper.c: use tls_cipher_defaults() instead of hardcoded BR_TLS_* cipher list in context initializer
- tls_engine.c: remove delayed-encryption buffering, simplify to thin BearSSL engine wrapper
- tls_engine.c: add session info accessors (tls_engine_get_version, get_cipher, get_ecdhe_curve, get_server_name, last_error)
- tls.h: add tls_state_* flags (SENDAPP, RECVAPP, SENDREC, RECVREC, CLOSED) abstracting BR_SSL_* constants
- tls.h: add tls_cipher_defaults() and tls_pipe_set_engine() declarations
- tls.h: remove delayed-encryption fields from struct tls_context
- tls_cipher.c: add tls_cipher_defaults() for programmatic default cipher initialization
- tls_cipher.c: add 3DES_EDE_CBC_SHA to shared tls_ciphers[] table
- main_tlswrapper_test.c: replace local cipher table with tls_ciphers[] lookup, use tls_state_CLOSED
- conn.c: upgrade conn API to return duplicate file descriptors for separate read/write tracking
- conn.c: add conn_findslot(), conn_closeslot(), conn_reset() helpers
- main_tlswrapper_tcp.c: rework to use separate read/write descriptors with half-close support
- main_tlswrapper_tcp.c: preserve outbound TCP traffic after remote EOF
- main_tlswrapper_smtp.c: adapt to new conn() API returning descriptor pair
- connectioninfo.c: use log_ipport() for compact connection info logging
- tests/test-tlswrapper.py: major expansion of delayed-encryption and STARTTLS test coverage

## 20260402

- conn.c: adjust connect logging
- main_tlswrapper_tcp.c: remove log message with non-existing proxy-protocol version2
- tests: added and reorganized TCP/SMTP/STARTTLS coverage, including `tlswrappernojail-tcp`
- add comments to all *.c files, clang-format
- conn.c: clean up parallel connects on fast success and poll errors
- tls_keyjail.c: initialize AES backends inside the keyjail process
- update log library to version 20260329
- update alloc library to version 20260329
- replace strtonum by parsenum library
- fix compiler warnings in timeoutread/timeoutwrite
- main_tlswrapper_{tcp,smtp}: use alloc_freeall in cleanup
- Makefile: temp. disable new python tests
- parsenum.c: remove SPDX-License-Identifier
- LICENCE -> LICENSE.md
- README.md: add Delayed-encryption

## 20260312

- tls_keyjail.c: validate seed_len
- tls_pipe.c: return NULL on encrypt failure instead of random data
- fix buffer size mismatch when reading into outbuf
- fix copy-paste error: wipe remoteport instead of remoteip twice
- tls_keyjail.c: abort on unknown cipher suite in key-jail handler
- tls_seccrt.c: abort on unknown secret-key type in PEM parser
- jail.c: fix log message displaying gid instead of uid
- tests: fixed badkey exit handling and improved `main_tlswrapper_test.c` validation, waitpid, child-exit, and pipe handling
- tls_ecdhe.c: remove const qualifier for ecdhe_copy
- fix typo: tlswraper" -> tlswrapper
- documentation: grammar fixes, corrected AES_128_CBC_SHA256 text, and updated examples
- main_tlswrapper.c: fix error message: -U is not compatible with -n
- jail.c: fix typo in comment
- randombytes.c: guard fcntl call against invalid file descriptor
- main_tlswrapper_smtp.c: replace die() with _exit() in SMTP signal handler
- main_tlswrapper.c: remove async-signal-unsafe logging from signal handler
- main_tlswrapper_smtp.c: initialize properly greylist response per request
- man/tlswrapper.1: fix TLS1.3 TODO -> not implemented
- main_tlswrapper.c: fix typo in comment
- log.[ch] version 20260221
- makefilegen.sh: use gcc -isystem /usr/local/include -MM
- main_tlswrapper.c: stop spinning when the delayed STARTTLS control pipe closes early
- resolvehost.c: encode resolver failures explicitly
- jail_poll.c: reject unsupported file descriptors in jail_poll() select fallback
- timeout{read,write}.c: validate file descriptors before FD_SET() and handle select() errors
- main_tlswrapper_smtp.c: add memory limits, reset envelope data between transactions
- tlswrapper-tcp: fix half-close after stdin EOF
- Makefile regenerate
- getentropyrandombytes/randombytes.c remove
- log.c remove SPDX-License-Identifier
- examples.md: fix example dovecot -> courier

## 20251001

- LICENCE update: CC0-1.0 OR 0BSD OR MIT-0 OR MIT
