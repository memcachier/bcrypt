package bcrypt

import (
  "strings"
  "testing"
)

func TestDefaultSalt(t *testing.T) {
  salt, err := GenSaltDefault()
  if err != nil {
    t.Errorf("Error generating salt: %s\n", err)
  }
  if !strings.HasPrefix(salt, "$2a") {
    t.Errorf("Salt has wrong prefix: %s\n", salt)
  }
  if len(salt) != 29 {
    t.Errorf("Salt has wrong length: %s\n", salt)
  }
}

func TestSalt(t *testing.T) {
  salt, err := GenSalt(12)
  if err != nil {
    t.Errorf("Error generating salt: %s\n", err)
  }
  if !strings.HasPrefix(salt, "$2a") {
    t.Errorf("Salt has wrong prefix: %s\n", salt)
  }
  if !strings.HasPrefix(salt, "$2a$12$") {
    t.Errorf("Salt has wrong work factor (12 expected): %s\n", salt)
  }
  if len(salt) != 29 {
    t.Errorf("Salt has wrong length: %s\n", salt)
  }
}

