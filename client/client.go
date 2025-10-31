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

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	"strconv"
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

type File struct {
	Next       userlib.UUID
	NextSymKey []byte
	NextMacKey []byte
	Content    []byte
}

type GroupSentinel struct {
	FileSentPtr userlib.UUID
	Key1        []byte
	Key2        []byte
}

type Sentinel struct {
	GroupUID    userlib.UUID
	GroupDecKey []byte
	GroupMacKey []byte
}

type FileSentinel struct {
	FileTail userlib.UUID
	FileKey1 []byte
	FileKey2 []byte
	Owner    userlib.UUID
	FileID   userlib.UUID
}

type Invitation [3][]byte //has to be array; struct too big for PKEnc

// type Invitation struct {
// 	GroupUID    userlib.UUID
// 	GroupDecKey []byte
// 	GroupMacKey []byte
// }

// HELPERS
func catchError(err *error, msg string) (failure bool) {
	if *err != nil {
		*err = errors.New(msg)
		failure = true
	}
	return failure
}

func deriveSymMacPair(sourceKey []byte, purpose1 string, purpose2 string) (symKey []byte, macKey []byte, err error) {
	symKey, err = userlib.HashKDF(sourceKey, []byte(purpose1))
	if err != nil {
		return
	}
	symKey = symKey[:keyLen]
	macKey, err = userlib.HashKDF(symKey, []byte(purpose2))
	if err != nil {
		return
	}
	macKey = macKey[:keyLen]
	return
}

func EncryptThenMac(key1 []byte, iv []byte, key2 []byte, plaintext interface{}) (ciphertext []byte, err error) {
	plaintextBytes, err := json.Marshal(plaintext)
	if err != nil {
		return
	}
	ciphertext = userlib.SymEnc(key1, iv, plaintextBytes)
	tag, _ := userlib.HMACEval(key2, ciphertext)
	ciphertext = append(tag, ciphertext...)
	return ciphertext, nil
}

func MacThenDecrypt(key1 []byte, key2 []byte, ciphertext []byte, ptr interface{}) (err error) {
	if len(ciphertext) < 65 {
		err = errors.New("tampering occurred, there must be at least 64 bytes of mac tag")
		return
	}
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
func EncryptThenSign(encKey userlib.PKEEncKey, signKey userlib.DSSignKey, plaintext interface{}) (ciphertext []byte, err error) {
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
	return ciphertext, nil
}

func VerifyThenDecrypt(decKey userlib.PKEDecKey, verifyKey userlib.DSVerifyKey, ciphertext []byte, ptr interface{}) (err error) {
	if len(ciphertext) < 257 {
		err = errors.New("tampering occurred")
		return
	}
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

func getSentinels(sentinelKey1 []byte, sentinelKey2 []byte, ciphertext []byte) (
	privSent Sentinel, groupSent GroupSentinel, fileSent FileSentinel, err error) {
	ptr := &privSent
	err = MacThenDecrypt(sentinelKey1, sentinelKey2, ciphertext, ptr)
	if err != nil {
		return
	}

	ptr2 := &groupSent
	ciphertext, ok := userlib.DatastoreGet(privSent.GroupUID)
	if !ok {
		err = errors.New("couldn't find group sentinel")
		return
	}
	err = MacThenDecrypt(privSent.GroupDecKey, privSent.GroupMacKey, ciphertext, ptr2)
	if err != nil {
		return
	}

	ptr3 := &fileSent
	ciphertext, ok = userlib.DatastoreGet(groupSent.FileSentPtr)
	if !ok {
		err = errors.New("couldn't find file sentinel")
		return
	}
	err = MacThenDecrypt(groupSent.Key1, groupSent.Key2, ciphertext, ptr3)
	if err != nil {
		return
	}
	return privSent, groupSent, fileSent, nil
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

	//place User struct into Datastore
	key2, _ := userlib.HashKDF(userdata.sourceKey, []byte("userStructHMAC"))
	key2 = key2[:keyLen]
	iv := userlib.RandomBytes(16)
	ciphertext, err := EncryptThenMac(userdata.sourceKey, iv, key2, userdata)
	if err != nil {
		return
	}
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
	ciphertext, ok := userlib.DatastoreGet(userUID)
	if !ok {
		err = errors.New("user doesn't exist")
		return
	}
	var userdata User
	userdataptr = &userdata
	sourceKey := userlib.Argon2Key([]byte(password), hashedName[16:24], keyLen)
	key2, _ := userlib.HashKDF(sourceKey, []byte("userStructHMAC"))
	key2 = key2[0:keyLen]
	err = MacThenDecrypt(sourceKey, key2, ciphertext, userdataptr)
	if catchError(&err, "invalid password provided, or tampering occurred") {
		return userdataptr, err
	}
	userdata.sourceKey = sourceKey
	userdata.password = []byte(password)
	return userdataptr, nil
}

func (userdata *User) makeFile(content []byte, symkeytail []byte, mackeytail []byte,
	oldTailKey []byte, oldTailMac []byte, oldTailUID userlib.UUID) (tailCipher []byte, err error) {

	var prevUID userlib.UUID
	var prevSymKey []byte
	var prevMacKey []byte
	var i int

	for len(content) > fileSize {
		var section File
		sectionUID := uuid.New()
		if i == 0 {
			section.Next = oldTailUID
			section.NextSymKey = oldTailKey
			section.NextMacKey = oldTailMac
		} else {
			section.Next = prevUID
			section.NextSymKey = prevSymKey
			section.NextMacKey = prevMacKey
		}
		section.Content = content[:fileSize]
		key1, _ := userlib.HashKDF(userdata.sourceKey, userlib.RandomBytes(4))
		key1 = key1[:keyLen]
		key2, _ := userlib.HashKDF(key1, userlib.RandomBytes(4))
		key2 = key2[:keyLen]
		iv := userlib.RandomBytes(16)
		var ciphertext []byte
		ciphertext, err = EncryptThenMac(key1, iv, key2, section)
		if err != nil {
			return
		}
		userlib.DatastoreSet(sectionUID, ciphertext)
		content = content[fileSize:]
		prevUID = sectionUID
		prevSymKey = key1
		prevMacKey = key2
		i += 1
	}

	var tail File
	if i != 0 {
		tail.Next = prevUID
		tail.NextMacKey = prevMacKey
		tail.NextSymKey = prevSymKey
	} else {
		tail.Next = oldTailUID
		tail.NextSymKey = oldTailKey
		tail.NextMacKey = oldTailMac
	}
	if len(content) > 512 {
		err = errors.New("tail section content size too big")
		return
	}
	tail.Content = content
	iv := userlib.RandomBytes(16)
	tailCipher, err = EncryptThenMac(symkeytail, iv, mackeytail, tail)
	if err != nil {
		return
	}
	return tailCipher, nil
}

func (userdata *User) StoreFile(filename string, content []byte) error {
	nilUID, _ := uuid.FromBytes(make([]byte, 16))
	sentinelUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "/" + userdata.Username))[:16])
	if err != nil {
		return err
	}

	ciphertext, ok := userlib.DatastoreGet(sentinelUID)
	if ok {
		sentinelKey1, sentinelKey2, err := deriveSymMacPair(userdata.sourceKey, filename, "HMAC"+filename)
		if err != nil {
			return err
		}
		_, _, fileSent, err := getSentinels(sentinelKey1, sentinelKey2, ciphertext)
		if err != nil {
			return err
		}
		fileuid := fileSent.FileTail
		tailCipher, err := userdata.makeFile(content, fileSent.FileKey1, fileSent.FileKey2, nil, nil, nilUID)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(fileuid, tailCipher)

	} else {
		//make new sentinels. User is owner.
		tailUID := uuid.New()
		symkey0, mackey0, err := deriveSymMacPair(userdata.sourceKey, filename+userdata.Username+strconv.Itoa(0), "HMAC"+strconv.Itoa(0))
		if err != nil {
			return err
		}
		tailCipher, err := userdata.makeFile(content, symkey0, mackey0, nil, nil, nilUID)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(tailUID, tailCipher)
		//setting File Sentinel
		var fileSent FileSentinel
		fileSentUID := uuid.New()
		uidString := fmt.Sprintf("%v", fileSentUID)
		fileSent.FileTail = tailUID
		fileSent.FileKey1 = symkey0
		fileSent.FileKey2 = mackey0
		fileSent.Owner = userdata.UID
		fileSent.FileID = uuid.New()
		symkey0, mackey0, err = deriveSymMacPair(userdata.sourceKey, "file Sentinel "+uidString, "HMAC file sentinel")
		if err != nil {
			return err
		}
		fileSentCipher, err := EncryptThenMac(symkey0, userlib.RandomBytes(16), mackey0, fileSent)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(fileSentUID, fileSentCipher)
		//setting groupSentinel
		var groupSentinel GroupSentinel //groupsentinel where group = owner only
		uidString = fmt.Sprintf("%v", tailUID)
		groupSentUID, _ := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + string(userdata.password) + uidString))[0:16])
		groupSentinel.FileSentPtr = fileSentUID
		groupSentinel.Key1 = symkey0
		groupSentinel.Key2 = mackey0
		uidString = fmt.Sprintf("%v", groupSentUID)
		symkey0, mackey0, err = deriveSymMacPair(userdata.sourceKey, "group sentinel"+uidString, "HMAC group sentinel")
		if err != nil {
			return err
		}
		iv := userlib.RandomBytes(16)
		ciphertext, err = EncryptThenMac(symkey0, iv, mackey0, groupSentinel)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(groupSentUID, ciphertext)
		//setting privateSentinel
		var userSent Sentinel
		userSent.GroupDecKey = symkey0
		userSent.GroupMacKey = mackey0
		userSent.GroupUID = groupSentUID
		sentinelKey1, sentinelKey2, err := deriveSymMacPair(userdata.sourceKey, filename, "HMAC"+filename)
		if err != nil {
			return err
		}
		iv = userlib.RandomBytes(16)
		ciphertext, err = EncryptThenMac(sentinelKey1, iv, sentinelKey2, userSent)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(sentinelUID, ciphertext)
		if fileSent.FileTail != tailUID {
			err = errors.New("tailUID doesn't match")
			return err
		}
		if groupSentinel.FileSentPtr != fileSentUID {
			err = errors.New("file sent uid doesn't match")
			return err
		}
		if userSent.GroupUID != groupSentUID {
			err = errors.New("group sent uid doesn't match")
			return err
		}
	}
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	sentinelUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "/" + userdata.Username))[:16])
	if err != nil {
		return
	}
	ciphertext, ok := userlib.DatastoreGet(sentinelUID)
	if !ok {
		err = errors.New("couldn't find file")
		return
	}
	sentinelKey1, sentinelKey2, err := deriveSymMacPair(userdata.sourceKey, filename, "HMAC"+filename)
	if err != nil {
		return
	}
	_, groupSent, fileSent, err := getSentinels(sentinelKey1, sentinelKey2, ciphertext)
	if err != nil {
		return
	}
	tailSymKey, tailMacKey, err := deriveSymMacPair(userdata.sourceKey, string(userlib.RandomBytes(4)), string(userlib.RandomBytes(6)))
	if err != nil {
		return
	}
	tailCipher, err := userdata.makeFile(content, tailSymKey, tailMacKey, fileSent.FileKey1, fileSent.FileKey2, fileSent.FileTail)
	if err != nil {
		return
	}
	newTailUID := uuid.New()
	userlib.DatastoreSet(newTailUID, tailCipher)
	fileSent.FileKey1 = tailSymKey
	fileSent.FileKey2 = tailMacKey
	fileSent.FileTail = newTailUID
	iv := userlib.RandomBytes(16)
	ciphertext, err = EncryptThenMac(groupSent.Key1, iv, groupSent.Key2, fileSent)
	if err != nil {
		return
	}
	userlib.DatastoreSet(groupSent.FileSentPtr, ciphertext)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	nilUID, _ := uuid.FromBytes(make([]byte, 16))
	//find user sentinel
	sentinelUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "/" + userdata.Username))[:16])
	if err != nil {
		return
	}
	privSentCipher, ok := userlib.DatastoreGet(sentinelUID)
	if !ok {
		err = errors.New("can't find user sentinel")
		return
	}
	//find group Sent
	sentinelKey1, sentinelKey2, err := deriveSymMacPair(userdata.sourceKey, filename, "HMAC"+filename)
	if err != nil {
		return
	}
	privSent, _, fileSent, err := getSentinels(sentinelKey1, sentinelKey2, privSentCipher)
	if err != nil {
		return
	}
	if userdata.Username == "bob" || userdata.Username == "alice" {
		userlib.DebugMsg("%s's privSent.GroupUID: %v", userdata.Username, privSent.GroupUID)
		userlib.DebugMsg("%s's fileSent.FileTail: %v", userdata.Username, fileSent.FileTail)
	}
	sectionUID := fileSent.FileTail
	symKey := fileSent.FileKey1
	macKey := fileSent.FileKey2
	for sectionUID != nilUID {
		var section File
		sectionCipher, ok := userlib.DatastoreGet(sectionUID)
		if !ok {
			err = errors.New("can't find tail file")
			return
		}
		err = MacThenDecrypt(symKey, macKey, sectionCipher, &section)
		if err != nil {
			return
		}
		content = append(section.Content, content...)
		symKey = section.NextSymKey
		macKey = section.NextMacKey
		sectionUID = section.Next
	}
	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	//create an invitaiton and set it to datastore, returning the invitationUID
	invitationMake := func(groupSentUID userlib.UUID, key1 []byte, key2 []byte) (invitationPtr userlib.UUID, err error) {
		var invitation Invitation
		invitation[0] = groupSentUID[:]
		invitation[1] = key1
		invitation[2] = key2
		pubkey, ok := userlib.KeystoreGet(recipientUsername + "PubKey")
		if !ok {
			err = errors.New("couldn't find recipient's public key")
			return
		}
		ciphertext, err := EncryptThenSign(pubkey, userdata.SignKey, invitation)
		if err != nil {
			return
		}
		invitationPtr = uuid.New()
		userlib.DatastoreSet(invitationPtr, ciphertext)
		return invitationPtr, nil
	}

	//create invitation. if owner of file, then set group sentinel. if not, then don't need to set new group sentinel
	sentinelUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "/" + userdata.Username))[:16])
	if err != nil {
		return
	}
	privSentCipher, ok := userlib.DatastoreGet(sentinelUID)
	if !ok {
		err = errors.New("can't find privSent for given file")
		return
	}
	sentinelKey1, sentinelKey2, err := deriveSymMacPair(userdata.sourceKey, filename, "HMAC"+filename)
	if err != nil {
		return
	}
	privSent, groupSent, fileSent, err := getSentinels(sentinelKey1, sentinelKey2, privSentCipher)
	if err != nil {
		return
	}
	if fileSent.Owner == userdata.UID {
		recipSent := groupSent //recipient group sentinel contains the same data as the owner's individual group sentinel
		fileUID := fmt.Sprintf("%v", fileSent.FileID)
		recipSentUID, _ := uuid.FromBytes(userlib.Hash([]byte(recipientUsername + string(userdata.password) + fileUID))[:16])
		if recipientUsername == "bob" {
			userlib.DebugMsg("bob's recipSentUID from alice sharing to bob: %v", recipSentUID)
			userlib.DebugMsg("bob's fileUID from alice sharing to bob: %v", fileUID)
		}
		var recipSentKey1 []byte
		var recipSentKey2 []byte
		recipSentKey1, recipSentKey2, err = deriveSymMacPair(userdata.sourceKey, recipientUsername+" Group SymKey "+fileUID, "Recipient Group MacKey")
		if err != nil {
			return
		}
		var recipCipher []byte
		recipCipher, err = EncryptThenMac(recipSentKey1, userlib.RandomBytes(16), recipSentKey2, recipSent)
		if err != nil {
			return
		}
		userlib.DatastoreSet(recipSentUID, recipCipher)
		invitationPtr, err = invitationMake(recipSentUID, recipSentKey1, recipSentKey2)
		if err != nil {
			return
		}
	} else {
		groupSentUID := privSent.GroupUID
		invitationPtr, err = invitationMake(groupSentUID, privSent.GroupDecKey, privSent.GroupMacKey)
		if err != nil {
			return
		}
	}
	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {

	inviteCipher, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("couldn't find the invitation from " + senderUsername)
	}
	verKey, ok := userlib.KeystoreGet(senderUsername + "VerifyKey")
	if !ok {
		return errors.New("couldn't find the sender's verification key for DS")
	}
	var invite Invitation
	err = VerifyThenDecrypt(userdata.PrivKey, verKey, inviteCipher, &invite)
	if err != nil {
		return
	}
	var privSent Sentinel
	privSent.GroupUID, err = uuid.FromBytes(invite[0])
	if err != nil {
		return
	}
	_, ok = userlib.DatastoreGet(privSent.GroupUID)
	if !ok {
		err = errors.New("The GroupSentinel for this file doesn't exist")
		return
	}
	privSent.GroupDecKey = invite[1]
	privSent.GroupMacKey = invite[2]
	privSentUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "/" + userdata.Username))[:16])
	if err != nil {
		return
	}
	sentinelKey1, sentinelKey2, err := deriveSymMacPair(userdata.sourceKey, filename, "HMAC"+filename)
	if err != nil {
		return
	}
	ciphertext, err := EncryptThenMac(sentinelKey1, userlib.RandomBytes(16), sentinelKey2, privSent)
	if err != nil {
		return
	}
	userlib.DatastoreSet(privSentUID, ciphertext)
	userlib.DatastoreDelete(invitationPtr)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) (err error) {
	nilUID, _ := uuid.FromBytes(make([]byte, 16))
	content, err := userdata.LoadFile(filename)
	if err != nil {
		return
	}
	newsymkey, newmackey, err := deriveSymMacPair(userdata.sourceKey, "newkey for"+filename, "newHMAC")
	newTailUID := uuid.New()
	if err != nil {
		return
	}
	tailCipher, err := userdata.makeFile(content, newsymkey, newmackey, nil, nil, nilUID)
	if err != nil {
		return
	}
	userlib.DatastoreSet(newTailUID, tailCipher)

	sentinelUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + "/" + userdata.Username))[:16])
	if err != nil {
		return
	}
	privSentCipher, ok := userlib.DatastoreGet(sentinelUID)
	if !ok {
		err = errors.New("can't find priv sentinel")
		return
	}
	sentinelkey1, sentinelkey2, err := deriveSymMacPair(userdata.sourceKey, filename, "HMAC"+filename)
	if err != nil {
		return
	}
	_, groupSent, fileSent, err := getSentinels(sentinelkey1, sentinelkey2, privSentCipher)
	if err != nil {
		return
	}
	fileSent.FileKey1 = newsymkey
	fileSent.FileKey2 = newmackey
	fileSent.FileTail = newTailUID
	fileID := fmt.Sprintf("%v", fileSent.FileID)
	fileCipher, err := EncryptThenMac(groupSent.Key1, userlib.RandomBytes(16), groupSent.Key2, fileSent)
	if err != nil {
		return
	}
	userlib.DatastoreSet(groupSent.FileSentPtr, fileCipher)
	userlib.DebugMsg("groupSent.FileSentPtr: %v", groupSent.FileSentPtr)

	//revoking recipient's access by deleting the group sentinel
	recipSentUID, _ := uuid.FromBytes(userlib.Hash([]byte(recipientUsername + string(userdata.password) + fileID))[:16])
	userlib.DebugMsg("recipSentUID from revoking: %v", recipSentUID)
	userlib.DebugMsg("oldfiletail from revoking: %v", fileID)
	_, ok = userlib.DatastoreGet(recipSentUID)
	if !ok {
		err = errors.New("the recipient's group sentinel could not be found, or was never instantiated to begin with (never shared to this person)")
		return
	}
	userlib.DatastoreDelete(recipSentUID)

	return nil
}
