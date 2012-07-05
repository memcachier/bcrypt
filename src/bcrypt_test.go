package bcrypt

import (
  "strings"
  "testing"
)

func TestSalt(t *testing.T) {
  salt, err := GenSalt(12)
  if err != nil {
    t.Errorf("Error generating salt: %s\n", err)
  }
  if !strings.HasPrefix(string(salt), "$2a") {
    t.Errorf("Salt has wrong prefix: %s\n", salt)
  }
  if !strings.HasPrefix(string(salt), "$2a$12$") {
    t.Errorf("Salt has wrong work factor (12 expected): %s\n", salt)
  }
  if len(salt) != 29 {
    t.Errorf("Salt has wrong length: %s\n", salt)
  }
}

func TestCrypt(t *testing.T) {
  var plains = [10]string{
    "hello world",
    "a",
    "b",
    "how how how",
    "asdasdasdasdasdadafsfdsafsdafdsafasdfsda",
    "password",
    "yes!",
    "",
    "99999999999999",
    "000000%&(#@&(@#&(*$#&##)))",
  }
  for _, p := range(plains) {
    testOneCrypt(p, t)
  }
}

func testOneCrypt(plain string, t *testing.T) {
  salt, err := GenSalt(DEFAULT_COST)
  if err != nil {
    t.Errorf("Error generating salt: %s\n", err)
  }

  cipher, err := Crypt(plain, salt)
  if err != nil {
    t.Errorf("Error generating cipher text: %s\n", err)
  }
  if cipher == plain {
    t.Errorf("Cipher text == plain text!")
  }
  if len(cipher) != 60 {
    t.Errorf("Cipher text isn't 60 in length! len:", len(cipher), ", cipher:",
      cipher)
  }
  if !strings.HasPrefix(cipher, string(salt)) {
    t.Errorf("Cipher text doesn't have its salt as prefix! salt:", string(salt),
      ", cipher:", cipher)
  }

  match, err := Verify(plain, cipher)
  if err != nil {
    t.Errorf("Error verifying cipher text and plain text match: %s\n", err)
  }
  if !match {
    t.Errorf("Plain text and cipher text don't verify!", cipher, " !<verify>",
      plain)
  }

  match, err = Verify(plain + "a", cipher)
  if err != nil {
    t.Errorf("Error verifying cipher text and plain text match: %s\n", err)
  }
  if match {
    t.Errorf("Plain text and cipher text verify when they shouldn't!", cipher,
      " !<verify>", plain)
  }
}

func TestBadSalt(t *testing.T) {
  cipher, err := Crypt("hello world", BcryptSalt("bad salt"))
  if err == nil {
    t.Errorf("Used bad salt with no error!")
  }
  if len(cipher) != 0 {
    t.Errorf("Bad salt returned something for crypt!", cipher)
  }
}

func TestChangedSalt(t *testing.T) {
  salt1, err := GenSalt(DEFAULT_COST)
  if err != nil {
    t.Errorf("Error generating salt: %s\n", err)
  }


  salt2, err := GenSalt(DEFAULT_COST)
  if err != nil {
    t.Errorf("Error generating salt: %s\n", err)
  }

  if salt1 == salt2 {
    t.Errorf("Generated two salts and they matched!", salt1, salt2)
  }

  cipher1, err := Crypt("hello world", salt1)
  if err != nil {
    t.Errorf("Error generating cipher text!", err)
  }

  cipher2, err := Crypt("hello world", salt2)
  if err != nil {
    t.Errorf("Error generating cipher text!", err)
  }

  if cipher1 == cipher2 {
    t.Errorf("Generated two ciphers with same plain text but different salt" +
      " and they matched!")
  }
}

// NOTE: Below tests were taken from
// https://github.com/jameskeane/bcrypt/blob/master/bcrypt_test.go
// and
// https://github.com/codahale/bcrypt-ruby/blob/master/spec/bcrypt/engine_spec.rb

type TestString struct {
	plain string
	salt  string
	hash  string
}

var testHashes []TestString = []TestString{
	{"", "$2a$06$DCq7YPn5Rq63x1Lad4cll.",
		"$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."},
	{"", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.",
		"$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye"},
	{"", "$2a$10$k1wbIrmNyFAPwPVPSVa/ze",
		"$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW"},
	{"", "$2a$12$k42ZFHFWqBp3vWli.nIn8u",
		"$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO"},
	{"a", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO",
		"$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"},
	{"a", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe",
		"$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V."},
	{"a", "$2a$10$k87L/MF28Q673VKh8/cPi.",
		"$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u"},
	{"a", "$2a$12$8NJH3LsPrANStV6XtBakCe",
		"$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS"},
	{"abc", "$2a$06$If6bvum7DFjUnE9p2uDeDu",
		"$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"},
	{"abc", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O",
		"$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm"},
	{"abc", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.",
		"$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi"},
	{"abc", "$2a$12$EXRkfkdmXn2gzds2SSitu.",
		"$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q"},
	{"abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGu",
		"$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"},
	{"abcdefghijklmnopqrstuvwxyz", "$2a$08$aTsUwsyowQuzRrDqFflhge",
		"$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz."},
	{"abcdefghijklmnopqrstuvwxyz", "$2a$10$fVH8e28OQRj9tqiDXs1e1u",
		"$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq"},
	{"abcdefghijklmnopqrstuvwxyz", "$2a$12$D4G5f18o7aMMfwasBL7Gpu",
		"$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG"},
	{"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$06$fPIsBO8qRqkjj273rfaOI.",
		"$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"},
	{"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$08$Eq2r4G/76Wv39MzSX262hu",
		"$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW"},
	{"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe",
		"$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"},
	{"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$12$WApznUOJfkEGSmYRfnkrPO",
		"$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC"},
  // test values from OpenWall...
  {"U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
    "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"},
  {"U*U*", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
    "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"},
  {"U*U*U", "$2a$05$XXXXXXXXXXXXXXXXXXXXXO",
    "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a"},
  {"", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
    "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy"},
  {"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "$2a$05$abcdefghijklmnopqrstuu",
    "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui"},
}

func TestPrecomputedHashes(t *testing.T) {
	for i, test := range testHashes {
		hash, err := Crypt(test.plain, BcryptSalt(test.salt))
		if err != nil {
			t.Errorf("Hash(%d): %v", i, err)
			continue
		}
		if hash != test.hash {
			t.Errorf("test(%d): equal: %v", i, hash)
			t.Errorf("test(%d): equal: %v", i, test.hash)
		}
	}

	for _, r := range []uint{4, 8, 14} {
		test := testHashes[r]
		salt, err := GenSalt(r)
		hash, err := Crypt(test.plain, salt)
    match, err := Verify(test.plain, hash)
		if !match {
			t.Errorf("Rounds(%d): %v", r, err)
		}
	}
}

