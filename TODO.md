# TODO

## API

Have:
* func Crypt(password string, salt string) string
* func Verify(password string, hashed_password string) bool
* func GenSalt(cost int) (salt string, err error)

Want?
* A type that is initialized (will basically generate a salt and reuse
  for all passwords)....?
* []byte interface versions?

## Implementation

* Use subtle package & do comparison at byte level:
  http://golang.org/pkg/crypto/subtle/
* May be better to have a C wrapper first instead of doing malloc and
  co in Go...
* Test performance of various entry options: e.g crypt_r Vs. crypt_ra
  Vs. a new entry point that allocates the working space on the stack
  instead of heap.
* Write a test that checks for memory leaks

# Resources for learning:

* OpenWall:
  http://www.openwall.com/Owl/

* Ruby:
  https://github.com/codahale/bcrypt-ruby
  https://github.com/codahale/bcrypt-ruby/blob/master/lib/bcrypt.rb
  https://github.com/codahale/bcrypt-ruby/blob/master/ext/mri/bcrypt_ext.c

* Older Go Bcrypt:
  https://bitbucket.org/zoowar/bcrypt/src/d863ac6dc426/bcrypt.go

* Native Go Bcrypt:
  https://github.com/jameskeane/bcrypt/blob/master/bcrypt.go

* Perl:
  http://search.cpan.org/~zefram/Crypt-Eksblowfish/lib/Crypt/Eksblowfish/Bcrypt.pm

When done should list here: http://godashboard.appspot.com/

