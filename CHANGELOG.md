## 20260413

- tls relay: distinguish wrapped-child `SIGCHLD` from helper `SIGCHLD`, preserve child output draining on child exit, and delay TLS shutdown until both child directions are closed
- tls relay: handle `SIGALRM` through the self-pipe loop and tighten finish-timeout behavior during child-exit cleanup
- main_tlswrapper.c: rename relay descriptors and log labels to consistently use `peerin`, `peerout`, and `childctl`
- logging: use "TLS" instead of "SSL" in updated log messages
- tests: expand `test-tlswrapper` coverage for child-exit EOF paths, forced child-stdout-close reads, clean `close_notify` handling, large reply completion, in-flight payload delivery after child stdout EOF,
  idle-peer shutdown after child stdout EOF, and delayed child replies after peer EOF

## 20260408

- refactor: split relay logic into cleartext and TLS phases with explicit FD tracking and half-close handling; abstract TLS API to remove BearSSL references from `main_tlswrapper.c`
- conn.[ch]: `conn()` now returns a descriptor pair, enabling separate read/write-side handling
- main_tlswrapper.c: fix TLS/STARTTLS phase completion around peer EOF, child exit, immediate child stdout EOF, and stale progress detection
- main_tlswrapper.c: tighten TLS poll conditions, validate `waitpid()` status handling, add `report_tls_phase_fds` tracing, and close child fds on `SIGCHLD`
- main_tlswrapper.c: half-close network after TLS child EOF; harden STARTTLS transition in cleartext relay loop
- main_tlswrapper_tcp.c: fix copy-paste error in cleanup: wipe `remoteport` instead of `remoteip` twice
- main_tlswrapper_tcp.c: preserve outbound traffic after remote EOF, handle half-close more precisely
- fd.[ch]: add `fd_close_read()`/`fd_close_write()` and `fd_close_enable()`/`fd_close_disable()` helpers
- fd.c: absorb blocking.c into `fd_blocking_enable()`/`fd_blocking_disable()`; simplify close handling to always try `shutdown()`
- logging: rework log plumbing, add `tls_alert_str()`, make `log_set_id(0)` initialize from environment or random
- correctness: rename header guards to avoid reserved identifiers, mark exit helpers as `noreturn`, wrap die macros in `do-while(0)`, make void pointer casts explicit, initialize `hostport` colon position, return const from `iptostr`, remove unreachable fallback in `tlswrapper.c`
- tests: extend `test-tlswrapper.py`/`.sh`/`.exp` with EOF propagation, half-close, STARTTLS, and timeout scenarios; fix `test-okcert.sh` CMD accumulation
- man/tlswrapper.1: remove the "experimental" label from delayed encryption (`-n`)
- build: refresh `Makefile`/`tests/Makefile` and apply `clang-format` cleanup in touched sources

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
