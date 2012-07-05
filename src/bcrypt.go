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

const (
  default_cost = 10
  min_cost = 4
  salt_length = 16

  // taken from ruby-bcrypt library
  salt_prefix = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"
)

// Crypt encrypts a plain text password with given salt.
func Crypt(password string, salt string) string {
  data   := C.malloc(C.CRYPT_OUTPUT_SIZE)
  out, _ := C.crypt_r(C.CString(password), C.CString(salt), data)
  result := C.GoString(out)
  C.free(data)
  return result
}

// Verify checks if a plain text password matches a bcrypt encrypted password.
func Verify(password string, hashed_password string) bool {
  return Crypt(password, hashed_password) == hashed_password
}

// GenSaltDefault generates a new salt with a default work factor.
func GenSaltDefault() (salt string, err error) {
  return GenSalt(default_cost)
}

// GenSalt generates a valid salt with the work factor given. Note the cost is
// an exponential factor.
func GenSalt(cost uint) (salt string, err error) {
  if (cost < min_cost) {
    cost = min_cost
  }

  // generate random bytes
  r := make([]byte, salt_length)
  l, err := rand.Read(r)
  if err != nil {
    return "", err
  }
  if l != salt_length {
    return "", nil // TODO: Return correct error
  }

  out, _ := C.crypt_gensalt_ra(C.CString(salt_prefix), C.ulong(cost),
    C.CString(string(r)), C.int(salt_length))
  // TODO: check for null
  result := C.GoString(out)
  C.free(unsafe.Pointer(out))
  return result, nil
}

