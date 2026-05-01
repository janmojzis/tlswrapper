## 20260501

- summary of changes since full release 20251001
- code refactoring: substantial cleanup and restructuring of the relay/TLS/STARTTLS code paths, with focus on clearer separation of phases, more reliable EOF and half-close handling, better descriptor management, and improved code documentation
- bug fixes: fixes for SMTP greylist response bounds, empty `MAIL FROM:` / `RCPT TO:` handling, outgoing PROXY protocol header generation, half-close and child-exit behavior, timeout/alarm edge cases, and several smaller correctness issues in buffer handling, logging, and cleanup paths
- hardening: stricter STARTTLS transition handling, tighter validation of parser inputs, SNI and certificate selection, jail uid/gid and memory-limit handling, resolver/address-family/file-descriptor checks
- tests, build, and documentation: significant expansion and reorganization of TCP/SMTP/STARTTLS regression tests, separation of Python-based tests, refreshed generated build files, and updates to manuals, README, examples, and in-source comments

## 20260428 (pre-release)

- STARTTLS/relay: harden the STARTTLS transition with a dedicated ack pipe, drop pipelined plaintext after STARTTLS, tighten bootstrap/handshake alarm handling
- jail.c: reject privileged jail accounts with `uid == 0` or `gid == 0` and derive jail uid/gid deterministically only from the pid
- parsing: replace `strtoip`/`strtoport`/`hostport` with `parseip`/`parseport`/`parsehostport`; add `parsename()` and validate SNI `server_name` before certificate-directory lookups
- tls_profile.c: downgrade missing-certificate logging from warning to debug level
- tls_keyjail.c: clear the PEM encryption key after signing
- main_tlswrapper_smtp.c: reset `alarm()`/`SIGALRM` before running the child
- writeall.c: handle zero-length writes and poll failures more robustly
- tests/build: move Python tests to a separate `pythontest` target, expand STARTTLS and relay coverage

## 20260418 (pre-release)

- main_tlswrapper_smtp.c: limit greylist response size to `SMTP_MAX_LINE` and fix an out-of-bounds read on empty `MAIL FROM:` / `RCPT TO:` lines
- alloc.[ch]: add `alloc_limit()` with `RLIMIT_AS`/`RLIMIT_DATA` fallback
- jail.c: treat memory limits as best-effort, set `RLIMIT_AS` as well, and use the allocator limit as a fallback safeguard
- tls_keyjail.c: use a signed offset for record exchange between the parent and keyjail and validate the offset range
- main_tlswrapper_tcp.c: increase the TCP buffer `4096->8192` and fix the `sizeof` bug when generating the outgoing PROXY header
- proxyprotocol.c: zero-initialize the PROXY v1 header buffer
- connectioninfo.c: reject unknown address families in `connectioninfo_fromfd()`
- fd.c: warn on failed `fcntl(F_GETFL/F_GETFD)`
- writeall.c: drop `POLLERR` from the `writeall()` event mask
- stralloc.c: avoid undefined behavior in `stralloc_catnum0()` for `LLONG_MIN`
- e.c: remove duplicate `ENODEV` / `EREMOTE` entries from `e_str()`
- tls_pem.c: clarify the ChaCha20 nonce comment in PEM encryption
- tests: disable flaky tests for chunked responses after half-EOF

## 20260416 (pre-release)

- fd.[ch]: add `fd_read()`/`fd_write()` wrappers with length capping (1 MiB), `EWOULDBLOCK`→`EAGAIN` normalization, and optional tracing; `fd_close_read()`/`fd_close_write()` now accept a descriptor name for tracing; `tryshutdown()` returns success status; add `tryclose()` helper
- main_tlswrapper.c, main_tlswrapper_tcp.c: switch all raw `read()`/`write()` calls to `fd_read()`/`fd_write()`, removing inline I/O logging now handled by the fd layer
- stralloc.c: keep capacity unchanged when growth allocation fails; fix compiler warnings
- alloc.[ch]: add configurable `alloc_MAX` limit with explicit error message on overflow
- tls_pubcrt.c: stop append after the first allocation failure
- log.[ch]: add `log_errno()` public API
- tests: replace STARTTLS sleep-based sync with `select`-driven waits, reduce inflight payload sizes

## 20260413 (pre-release)

- tls relay: distinguish wrapped-child `SIGCHLD` from helper `SIGCHLD`, preserve child output draining on child exit, and delay TLS shutdown until both child directions are closed
- tls relay: handle `SIGALRM` through the self-pipe loop and tighten finish-timeout behavior during child-exit cleanup
- main_tlswrapper.c: rename relay descriptors and log labels to consistently use `peerin`, `peerout`, and `childctl`
- logging: use "TLS" instead of "SSL" in updated log messages
- tests: expand `test-tlswrapper` coverage for child-exit EOF paths, forced child-stdout-close reads, clean `close_notify` handling, large reply completion, in-flight payload delivery after child stdout EOF,
  idle-peer shutdown after child stdout EOF, and delayed child replies after peer EOF

## 20260408 (pre-release)

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

## 20260402 (pre-release)

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

## 20260312 (pre-release)

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
