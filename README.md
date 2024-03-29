# Description

The tlswrapper is an TLS encryption wrapper between remote client and local program prog. Systemd.socket/inetd/tcpserver/... creates the server connection, tlswrapper encrypts/decrypts data
stream and reads/writes data from/to the program prog as follows:

Internet <--> systemd.socket/inetd/tcpserver/... <--> tlswrapper <--> prog

# Security
 

## Separate process for every connection

The tlswrapper is executed from systemd.socket/inetd/tcpserver/... which runs separate instance of tlswrapper for each TLS connection. It ensures that a vulnerability in the code (e.g. bug in the TLS library) can't be used to compromise the memory of another connection.

## Separate process for network connection and separate process for secret-key operation

To protect against secret-information leaks to the network connection (such Heartbleed) tlswrapper runs two independent processes for every TLS connection. One process holds secret-keys and
runs secret-keys operations and second talks to the network. Processes communicate with each other through UNIX pipes.

## JAIL - Privilege separation, filesystem isolation, limits

The tlswrapper processes run under dedicated non-zero uid to prohibit kill, ptrace, etc. Is chrooted into an empty, unwritable directory to prohibit filesystem access. Sets ulimits to prohibit new files, sockets, etc. Sets ulimits to prohibit forks.

## PEM files

The tlswrapper uses for simplicity both secret-key and certificates in one PEM file. When the server starts, runs two independent UNIX processes, one for network communication, second for secret-key operations. The network-process is immediately jailed and starts TLS handshake. Secret-key-process starts under root privileges, waits when network-process receives SNI extension from
client-hello packet. Then the network-process assemble the PEM filename and sends the name to the secret-key-process. Secret-key-process loads the PEM file and immediatelly is jailed and drops it's
privileges. Since here both processes runs jailed (see JAIL above). Note that PEM files are loaded under root privileges, but parsed in jailed unpriviledged process. It ensures that a vulnerability in the
parsing code can't be used to gain root privileges/informations. Warning: For security tlswrapper replaces any slash-dots in PEM filename with slash-colons before opening.

## TLS library

The tlswrapper uses BearSSL. BearSSL is an implementation of the SSL/TLS protocol (RFC 5246) written in C. It aims at offering the following features:
- Be correct and secure. In particular, insecure protocol versions and choices of algorithms are not supported, by design; cryptographic algorithm implementations are constant-time by default.
- Be small, both in RAM and code footprint. For instance, a minimal server implementation may fit in about 20 kilobytes of compiled code and 25 kilobytes of RAM.
- Be highly portable. BearSSL targets not only big operating systems like Linux and Windows, but also small embedded systems and even special contexts like bootstrap code.
- Be feature-rich and extensible. SSL/TLS has many defined cipher suites and extensions; BearSSL should implement most of them, and allow extra algorithm implementations to be added afterwards, possibly from third parties.

# Examples
- [examples page](examples.md)
