package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// Useful const's
const keyLen = 16
const fileSize = 512

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username  string
	UID       userlib.UUID
	password  []byte //password and sourceKey are not placed on Datastore
	sourceKey []byte
	PrivKey   userlib.PKEDecKey
	SignKey   userlib.DSSignKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// type FileHead struct {
// 	next    *File
// 	tail    *File
// 	content []byte
// }
// type File struct {
// 	next    *File
// 	content []byte
// }

// HELPERS
func catchError(err *error, msg string) (failure bool) {
	if *err != nil {
		*err = errors.New(msg)
		failure = true
	}
	return failure
}

func EncryptThenMac(key1 []byte, iv []byte, key2 []byte, plaintext interface{}) (ciphertext []byte) {
	plaintextBytes, err := json.Marshal(plaintext)
	if err != nil {
		return
	}

	ciphertext = userlib.SymEnc(key1, iv, plaintextBytes)
	tag, _ := userlib.HMACEval(key2, ciphertext)
	ciphertext = append(tag, ciphertext...)
	return ciphertext
}

func MacThenDecrypt(key1 []byte, key2 []byte, ciphertext []byte, ptr interface{}) (err error) {
	tag := ciphertext[0:64]
	content := ciphertext[64:]
	contentHash, _ := userlib.HMACEval(key2, content)
	ok := userlib.HMACEqual(tag, contentHash)
	if !ok {
		err = errors.New("failed integrity check")
		return
	}

	plaintextBytes := userlib.SymDec(key1, content)
	err = json.Unmarshal(plaintextBytes, ptr) //ptr should be a struct pointer, like User* or File*
	if catchError(&err, "Type mismatch between json and assignment struct") {
		return
	}
	return nil
}

// asymmetric encryption, then signing
func EncryptThenSign(encKey userlib.PKEEncKey, signKey userlib.DSSignKey, plaintext interface{}) (ciphertext []byte) {
	plaintextBytes, err := json.Marshal(plaintext)
	if err != nil {
		return
	}

	ciphertext, err = userlib.PKEEnc(encKey, plaintextBytes)
	if err != nil {
		return
	}
	sig, err := userlib.DSSign(signKey, ciphertext)
	if err != nil {
		return
	}
	ciphertext = append(sig, ciphertext...)
	return ciphertext
}

func VerifyThenDecrypt(decKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey, ciphertext []byte, ptr interface{}) (err error) {
	sig := ciphertext[0:256]
	content := ciphertext[256:]
	err = userlib.DSVerify(verifyKey, content, sig)
	if catchError(&err, "DS Verification failed") {
		return
	}
	plaintextBytes, err := userlib.PKEDec(decKey, content)
	if err != nil {
		return
	}
	err = json.Unmarshal(plaintextBytes, ptr)
	if catchError(&err, "Type mismatch between json and assignment struct") {
		return
	}
	return nil
}

// checks the given uid address in Datastore
func checkDatastore(uid userlib.UUID, minLen int) (ciphertext []byte, err error) {
	ciphertext, ok := userlib.DatastoreGet(uid)
	if !ok {
		err = errors.New("requested object doesn't exist")
		return
	}
	if len(ciphertext) < minLen {
		err = errors.New("tampering occurred")
		return
	}
	return ciphertext, nil
}

func CheckValidUsername(username string) (err error) {
	if username == "" {
		err = errors.New("not a valid username")
		return err
	}
	hashedName := userlib.Hash([]byte(username))
	userUID, _ := uuid.FromBytes(hashedName[0:16])
	_, ok := userlib.DatastoreGet(userUID)
	if ok {
		err = errors.New("user already exists")
		return err
	}
	return nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	err = CheckValidUsername(username)
	if err != nil {
		return
	}
	//init user struct
	var userdata User
	userdata.Username = username
	hashedName := userlib.Hash([]byte(username))
	userdata.UID, _ = uuid.FromBytes(hashedName[0:16])
	salt := hashedName[16:24]
	userdata.password = []byte(password)
	userdata.sourceKey = userlib.Argon2Key([]byte(password), salt, keyLen)
	//setting up asymm encryp
	pk, sk, _ := userlib.PKEKeyGen()
	keystoreId := userdata.Username + "PubKey"
	err = userlib.KeystoreSet(keystoreId, pk)
	if catchError(&err, "This user already has a public key set") {
		return
	}
	userdata.PrivKey = sk
	//setting up Digital Sig
	signk, vk, _ := userlib.DSKeyGen()
	keystoreId = userdata.Username + "VerifyKey"
	err = userlib.KeystoreSet(keystoreId, vk)
	if catchError(&err, "this user already has a verification key set") {
		return
	}
	userdata.SignKey = signk

	//place into Datastore
	key2, _ := userlib.HashKDF(userdata.sourceKey, []byte("userStructHMAC"))
	key2 = key2[0:keyLen]
	iv := userlib.RandomBytes(16)
	ciphertext := EncryptThenMac(userdata.sourceKey, iv, key2, userdata)
	userlib.DatastoreSet(userdata.UID, ciphertext)
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		err = errors.New("not a valid username")
		return
	}
	hashedName := userlib.Hash([]byte(username))
	userUID, _ := uuid.FromBytes(hashedName[0:16])
	ciphertext, err := checkDatastore(userUID, 64)
	if err != nil {
		return
	}
	var userdata User
	userdataptr = &userdata
	sourceKey := userlib.Argon2Key([]byte(password), hashedName[16:24], keyLen)
	key2, _ := userlib.HashKDF(sourceKey, []byte("userStructHMAC"))
	key2 = key2[0:keyLen]
	err = MacThenDecrypt(sourceKey, key2, ciphertext, userdataptr)
	// userlib.DebugMsg("READ FROM DATASTORE:")
	// userlib.DebugMsg("key1: %v, key2: %v", sourceKey, key2)
	// userlib.DebugMsg("tag: %v\n ciphertext: %v", ciphertext[0:64], ciphertext[64:94])
	if catchError(&err, "invalid password provided, or tampering occurred") {
		return userdataptr, err
	}
	userdata.sourceKey = sourceKey
	userdata.password = []byte(password)
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
