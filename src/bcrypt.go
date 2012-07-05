/*
  Go BCrypt Library

  Implemented as a wrapper around the OpenWall BCrypt implementation.
  http://www.openwall.com/crypt/

  bcrypt stores a setting string at the start of passwords, format of which
  is '$<version>$<cost>$<salt><checksum>'

  e.g., $2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa
        version  = '2a'
        cost     = '10'
        salt     = '$2a$10$vI8aWBnW3fID.ZQ4/zo1G.'
        checksum = 'q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa'
*/
package bcrypt

/*
#include <stdlib.h>
#include "ow-crypt.h"
*/
import "C"

import (
  "crypto/rand"
  "unsafe"
)

// Salt is a specially formatted string, so we use a new type to make users
// aware f this.
// e.g.,
//   salt     = '$2a$10$vI8aWBnW3fID.ZQ4/zo1G.'
//   version  = '2a'
//   cost     = '10'
//   random   = 'vI8aWBnW3fID.ZQ4/zo1G.'
type BcryptSalt string

const (
  DEFAULT_COST = 10
  min_cost = 4
  salt_length = 16

  // taken from ruby-bcrypt library
  salt_prefix = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"
)

// Crypt encrypts a plain text password with given salt.
func Crypt(plain string, salt BcryptSalt) (hashed string, err error) {
  cpass  := C.CString(password)
  defer C.free(unsafe.Pointer(cpass))
  csalt  := C.CString(string(salt))
  defer C.free(unsafe.Pointer(csalt))
  data   := C.malloc(C.CRYPT_OUTPUT_SIZE)
  defer C.free(data)

  out, err := C.crypt_r(cpass, csalt, data)
  if err != nil {
    return
  }

  hash = C.GoString(out)
  return
}

// Verify checks if a plain text password matches a bcrypt encrypted password.
func Verify(plain string, hashed string) (match bool, err error) {
  cipher, err := Crypt(password, BcryptSalt(hashed_password))
  if err != nil {
    return
  }
  match = cipher == hashed_password
  return
}

// GenSalt generates a valid salt with the work factor given. Note the cost is
// an exponential factor.
func GenSalt(cost uint) (salt BcryptSalt, err error) {
  if (cost < min_cost) {
    cost = min_cost
  }

  // generate random bytes
  r := make([]byte, salt_length)
  _, err = rand.Read(r)
  if err != nil {
    return
  }

  // crand := C.CString(string(r))
  // defer C.free(unsafe.Pointer(crand))
  crand := (*C.char)(unsafe.Pointer(&r[0]))
  csalt := C.CString(salt_prefix)
  defer C.free(unsafe.Pointer(csalt))

  out, err := C.crypt_gensalt_ra(csalt, C.ulong(cost), crand, C.int(salt_length))
  defer C.free(unsafe.Pointer(out))

  if err != nil {
    return
  }

  salt = BcryptSalt(C.GoString(out))
  return
}

