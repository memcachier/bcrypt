# BCrypt Readme

BCrypt is a go package that provides bcrypt password hashing
functions for Go. It does this by wrapping an existing C
implementation of bcrypt and providing a thread-safe Go binding to it.

## Interface (API)

~~~~ {.go}
func Crypt(plain string, salt BcryptSalt) (hashed string, err error)
func Verify(plain string, hashed string) (match bool, err error)
func GenSalt(cost uint) (salt BcryptSalt, err error)
type BcryptSalt string
~~~~

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

## Get involved!

We are happy to receive bug reports, fixes, documentation enhancements,
and other improvements.

Please report bugs via the
[github issue tracker](http://github.com/memcachier/bcrypt/issues).

Master [git repository](http://github.com/memcachier/bcrypt):

* `git clone git://github.com/memcachier/bcrypt.git`

## License

* This library is released under the BSD-3 licence.
* The OpenWall C BCrypt library (version 1.2) is public domain.

