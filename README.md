# GoBCrypt Readme

gogcrypt is a go package that provides bcrypt password hashing
functions for Go. It does this by wrapping an existing C
implementation of bcrypt and providing a thread-safe Go binding to it.

## Interface (API)

* func Crypt(password string, salt string) string
* func Verify(password string, hashed_password string) bool

## Why BCrypt?

The advantage of bcrypt for password hashing over other algorithms is
that bcrypt is designed to be slow and for the slowness to be a
fundamental and controllable part of the algorithm. This is a
desirable feature as computers are continually getting faster, that
makes brute-force attacks more viable over time as more passwords can
be tried per second. Bcrypt is future proof as you simply give it a
larger work factor, which makes it slower.

The original paper for bcrypt can be found at:
http://www.usenix.org/events/usenix99/provos.html

## Acknowledgements

The vast bulk of this package is the C implementation of bcrypt
(version 1.2). This was written by Solar Design
(http://www.openwall.com/crypt/).

## License

* This library is released under the BSD-3 licence.
* The OpenWall C BCrypt library (version 1.2) is released under the
  public domain.

