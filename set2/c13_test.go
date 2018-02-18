package main

import (
	"github.com/srinivengala/cryptopals/crytin"

	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"
)

//ECB cut-and-paste
//
//Write a k=v parsing routine, as if for a structured cookie. The routine should take:
//
//foo=bar&baz=qux&zap=zazzle
//
// ... and produce:
//
// {
//   foo: 'bar',
//   baz: 'qux',
//   zap: 'zazzle'
// }
//
// (you know, the object; I don't care if you convert it to JSON).
//
// Now write a function that encodes a user profile in that format, given an email address. You should have something like:
//
// profile_for("foo@bar.com")
//
// ... and it should produce:
//
// {
//   email: 'foo@bar.com',
//   uid: 10,
//   role: 'user'
// }
//
// ... encoded as:
//
// email=foo@bar.com&uid=10&role=user
//
// Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".
//
// Now, two more easy functions. Generate a random AES key, then:
//
//     Encrypt the encoded user profile under the key; "provide" that to the "attacker".
//     Decrypt the encoded user profile and parse it.
//
// Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.

// Notes:
// 1. push user to last block so we can replace with admin block
// email=X&uid=10&role=user
// 19 bytes to "user", blockAlign(19) = 32, 32-19=13
// email=1234567890123&uid=10&role=user
// 13bytes email id will push "user" be last block that
// need to be replaced with "admin" block.
//
// 2. insert 'email+admin block' so that admin takes and starts at a block, so we can harvest that block from cipher text
// leftBytes=6, blockAlign(6) = 16, 16-6=10
// email=123456admin67890123456&uid=10&role=user
// passing 6byte email + pad(admin) the second block of cipher text is admin block

var _unknownKey []byte

func init() {
	const ks = 16
	_unknownKey = make([]byte, ks)
	rand.Seed(time.Now().Unix())
	rand.Read(_unknownKey[:])
}

type user struct {
	Email string
	UID   int
	Role  string
}

func newUser(email string) (*user, error) {
	if hasMetaChars(email) {
		return nil, errors.New("Illegal character in email id")
	}
	return &user{Email: email, UID: 10, Role: "user"}, nil
}

func (u *user) URLEncode() string {
	return fmt.Sprintf("email=%s&uid=%d&role=%s", u.Email, u.UID, u.Role)
}

func (u *user) URLDecode(s string) {
	for _, kv := range strings.Split(s, "&") {
		ss := strings.Split(kv, "=")
		switch ss[0] {
		case "email":
			u.Email = ss[1]
		case "uid":
			u.UID, _ = strconv.Atoi(ss[1])
		case "role":
			u.Role = ss[1]
		}
	}
}

func hasMetaChars(s string) bool {
	return strings.ContainsAny(s, "&=")
}

func oracleEmail(email string) ([]byte, error) {
	u, err := newUser(email)
	if err != nil {
		return nil, err
	}
	encoded := u.URLEncode()
	fmt.Println("Encrypting : ", crytin.ToSafeString([]byte(encoded)))
	cb, _ := crytin.EncryptAesEcb([]byte(encoded), _unknownKey)
	return cb, nil
}

func verifyAdmin(cb []byte) bool {
	pb, _ := crytin.DecryptAesEcb(cb, _unknownKey)
	//fmt.Println(" The decrypted : ", crytin.ToHex(pb))
	fmt.Println(" The decrypted : ", string(pb))

	u := new(user)
	u.URLDecode(string(pb))
	if u.Role == "admin" {
		return true
	}
	return false
}

func TestPrivilegeEsclation(t *testing.T) {
	_ = t
	const ks = 16
	if _, err := newUser("te&st@test.com"); err == nil {
		t.Error("Could not detect metacharacters in email")
	}

	//13bytes email to push "user" to last block
	cb, _ := oracleEmail("ab@google.com")
	t.Log(" Hex cb :", crytin.ToHex(cb))

	//compute admin block, the second block of cipher text
	pb := []byte("admin")
	crytin.PKCS7Pad(&pb, ks)
	pb = append([]byte("ab@abc.com"), pb...)
	t.Log("To enc adminBlock : ", crytin.ToHex(pb))
	adminBlock, _ := oracleEmail(string(pb))
	adminBlock = adminBlock[ks : ks*2]

	t.Log("Hex adminBlock    : ", crytin.ToHex(adminBlock))
	copy(cb[len(cb)-ks:], adminBlock)
	t.Log(" Hex cb :", crytin.ToHex(cb))

	if !verifyAdmin(cb) {
		t.Error("Could not do privilege esclation")
	}
	t.Log("Privilege escalation successful")
}
