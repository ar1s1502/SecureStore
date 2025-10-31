package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	"strconv"
	_ "strconv"
	_ "strings"
	"testing"

	uuid "github.com/google/uuid"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("loadfile for contentOne")
			content, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("loadfile with contenttwo")
			content, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	var _ = Describe("Flag Tests - User Auth", func() {

		Specify("Flag Test: Test Invalid UserInit", func() {
			userlib.DebugMsg("Initlalizing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing second user with same username")
			charles, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing bob with empty username")
			bob, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Flag Test: Test Invalid GetUser 1", func() {
			userlib.DebugMsg("nonexistent user get")
			charles, err = client.GetUser("ADSF", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("wrongPW login")
			aliceLaptop, err = client.GetUser("alice", "wrongPassword")
			Expect(err).ToNot(BeNil())
		})

		Specify("Flag Test: Test GetUser on mod'd Datastore user struct", func() {
			userlib.DebugMsg("initializing alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			prevDatastore := userlib.DatastoreGetMap()
			userlib.DebugMsg("prevDatastore size: %d", len(prevDatastore))
			oldMap := make(map[userlib.UUID][]byte, len(prevDatastore))
			for key := range prevDatastore {
				userlib.DebugMsg("key: %v", key)
				oldMap[key], _ = userlib.DatastoreGet(key)
			}

			userlib.DebugMsg("init bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			currDatastore := userlib.DatastoreGetMap()
			userlib.DebugMsg("currDatastore size: %d", len(currDatastore))
			for key := range currDatastore {
				userlib.DebugMsg("key: %v", key)
			}

			userlib.DebugMsg("Mallory modifies all uid's involving Bob user")
			for key := range currDatastore {
				_, keyInMap := oldMap[key]
				userlib.DebugMsg("key %v", key)
				userlib.DebugMsg("keyInMap: %v", keyInMap)
				if !keyInMap {
					old, _ := userlib.DatastoreGet(key)
					userlib.DebugMsg("old cipher length: %d", len(old))
					userlib.DatastoreSet(key, userlib.RandomBytes(80))
					new, _ := userlib.DatastoreGet(key)
					userlib.DebugMsg("new cipher length: %d", len(new))
				}
			}

			userlib.DebugMsg("Bob tries to login")
			bob, err = client.GetUser("bob", defaultPassword)
			userlib.DebugMsg("Bob username: %s", bob.Username)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("modifying all of datastore...")
			datastore := userlib.DatastoreGetMap()
			for key := range datastore {
				userlib.DatastoreSet(key, userlib.RandomBytes(8))
			}

			userlib.DebugMsg("calling getUser from aliceLaptop after modifying datastore")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("initializing doris and charles")
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Clearing datastore...")
			userlib.DatastoreClear()

			userlib.DebugMsg("Calling get user for doris and charles should err")
			_, err = client.GetUser("doris", defaultPassword)
			Expect(err).ToNot(BeNil())
			_, err = client.GetUser("charles", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
	})

	var _ = Describe("Flag Tests - Load/Store/Append Files", func() {
		// Test 2: Test file overwrite, append, and multi-section file handling
		Specify("File Operations: Overwrite, append, and error handling", func() {

			bob, err := client.InitUser("bob", "password123")
			Expect(err).To(BeNil())

			initialContent := []byte("Initial content")
			err = bob.StoreFile("myfile.txt", initialContent)
			Expect(err).To(BeNil())

			loadedContent, err := bob.LoadFile("myfile.txt")
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(initialContent))

			newContent := []byte("Completely new content that replaces the old one")
			err = bob.StoreFile("myfile.txt", newContent)
			Expect(err).To(BeNil())

			loadedContent, err = bob.LoadFile("myfile.txt")
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(newContent))

			appendContent := []byte(" - This is appended text")
			err = bob.AppendToFile("myfile.txt", appendContent)
			Expect(err).To(BeNil())

			expectedContent := append(newContent, appendContent...)
			loadedContent, err = bob.LoadFile("myfile.txt")
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(expectedContent))

			for i := 0; i < 5; i++ {
				appendText := []byte("Append " + strconv.Itoa(i))
				err = bob.AppendToFile("myfile.txt", appendText)
				Expect(err).To(BeNil())
				expectedContent = append(expectedContent, appendText...)
			}

			loadedContent, err = bob.LoadFile("myfile.txt")
			Expect(err).To(BeNil())
			Expect(loadedContent).To(Equal(expectedContent))

			err = bob.AppendToFile("nonexistent.txt", []byte("test"))
			Expect(err).ToNot(BeNil(), "AppendToFile should fail on non-existent file")

			_, err = bob.LoadFile("anothernonexistent.txt")
			Expect(err).ToNot(BeNil(), "LoadFile should fail on non-existent file")
		})

		Specify("File operations with Datastore Adversary", func() {
			userlib.DebugMsg("initializing Alice, Bob, Charles, and Doris")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			prevDatastore := userlib.DatastoreGetMap()
			oldMap := make(map[userlib.UUID][]byte, len(prevDatastore))
			for k := range prevDatastore {
				oldMap[k], _ = userlib.DatastoreGet(k)
			}

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Mallory tries to load and append to alice's file")
			_, err := doris.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			err = doris.AppendToFile(aliceFile, []byte("random"))
			Expect(err).ToNot(BeNil())

			// userlib.DebugMsg("Mallory tries to read files on Datastore directly using json.Unmarshal")
			// for k := range userlib.DatastoreGetMap() {
			// 	_, kInMap := oldMap[k]
			// 	if !kInMap {
			// 		err = json.Unmarshal() Are we allowed to import encoding/json??
			// 	}
			// }

			userlib.DebugMsg("Mallory modifies all of Datastore")
			datastore := userlib.DatastoreGetMap()
			for key := range datastore {
				userlib.DatastoreSet(key, userlib.RandomBytes(8))
			}
			userlib.DebugMsg("Alice tries appending to and loading to file")
			err = alice.StoreFile(aliceFile, []byte("randomContent"))
			Expect(err).ToNot(BeNil())
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("File Operations with extremeley large files", func() {
			userlib.DebugMsg("initializing Alice, Bob, Charles, and Doris")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice stores and loads a large file")
			largeContent := userlib.RandomBytes(1500)
			err = alice.StoreFile(aliceFile, largeContent)
			Expect(err).To(BeNil())
			readContent, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(largeContent))
			userlib.DebugMsg("Alice appends a large chunk to the large file, then loads it again")
			err = alice.AppendToFile(aliceFile, largeContent)
			Expect(err).To(BeNil())
			readContent, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(append(largeContent, largeContent...)))

			prevDatastore := userlib.DatastoreGetMap()
			oldMap := make(map[userlib.UUID][]byte, len(prevDatastore))
			for k := range prevDatastore {
				oldMap[k], _ = userlib.DatastoreGet(k)
			}

			userlib.DebugMsg("Alice stores and loads a massive file")
			massiveContent := userlib.RandomBytes(91001)
			err = alice.StoreFile("massiveFile", massiveContent)
			Expect(err).To(BeNil())
			readContent, err = alice.LoadFile("massiveFile")
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(massiveContent))
			userlib.DebugMsg("Alice appends massive content to massive file")
			err = alice.AppendToFile("massiveFile", massiveContent)
			Expect(err).To(BeNil())
			readContent, err = alice.LoadFile("massiveFile")
			Expect(err).To(BeNil())
			Expect(len(readContent)).To(Equal(len(append(massiveContent, massiveContent...))))
			Expect(readContent).To(Equal(append(massiveContent, massiveContent...)))

			userlib.DebugMsg("Alice shares massive file to bob and charles")
			err = alice.StoreFile("massiveFile", massiveContent)
			Expect(err).To(BeNil())
			invite, err := alice.CreateInvitation("massiveFile", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			invite, err = alice.CreateInvitation("massiveFile", "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles, bob should see massiveFile")
			readContent, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(massiveContent))
			readContent, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(massiveContent))

			currDatastore := userlib.DatastoreGetMap()
			userlib.DebugMsg("Mallory modifies all places in Datastore that involve the massiveFile")
			for key := range currDatastore {
				_, keyInMap := oldMap[key]
				if !keyInMap {
					userlib.DatastoreSet(key, userlib.RandomBytes(1000))
				}
			}

			userlib.DebugMsg("Alice, bob, charles try loading and appending to the massiveFile after mallory mod's")
			_, err = alice.LoadFile("massiveFile")
			Expect(err).ToNot(BeNil())
			err = alice.AppendToFile("massiveFile", []byte("random"))
			Expect(err).ToNot(BeNil())

			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			err = bob.AppendToFile(bobFile, []byte("random"))
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
			err = charles.AppendToFile(charlesFile, []byte("random"))
			Expect(err).ToNot(BeNil())

		})
	})

	var _ = Describe("Flag Tests - File Sharing/Revocation", func() {

		Specify("Flag Test: Invalid CreateInvitations", func() {
			userlib.DebugMsg("initializing Alice, Bob, Charles")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates aliceFile.txt")
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice tries to share a nonexistent file to Bob")
			var invite userlib.UUID
			_, err = alice.CreateInvitation("asdfasdf", "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice tries to share to a nonexistent user")
			_, err = alice.CreateInvitation(aliceFile, "asdfadsf")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice shares to Bob, and Bob shares to Charles")
			invite, _ = alice.CreateInvitation(aliceFile, "bob")
			bob.AcceptInvitation("alice", invite, bobFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles appends to alice's file")
			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
		})

		Specify("Flag Test: Invalid AcceptInvitations", func() {
			userlib.DebugMsg("initializing Alice, Bob, Charles, and Doris")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice and Bob both create a file called " + aliceFile)
			alice.StoreFile(aliceFile, []byte(contentOne))
			bob.StoreFile(aliceFile, []byte(contentTwo))
			content, _ := alice.LoadFile(aliceFile)
			userlib.DebugMsg("alice "+aliceFile+" content :%s", content)
			content, _ = bob.LoadFile(aliceFile)
			userlib.DebugMsg("bob "+aliceFile+" content :%s", content)
			userlib.DebugMsg("Alice shares the file to Bob")
			invite, _ := alice.CreateInvitation(aliceFile, "bob")
			userlib.DebugMsg("Bob tries giving the file the same name " + aliceFile)
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())
			content, _ = alice.LoadFile(aliceFile)
			content2, _ := bob.LoadFile(aliceFile)
			userlib.DebugMsg("Alice and Bob's " + aliceFile + " should have the same content now")
			Expect(content).To(Equal(content2))

			userlib.DebugMsg("Mallory tries creating his own invitation, pretending to be alice")
			charles.StoreFile(charlesFile, []byte(contentThree))
			malloryInvitePtr, _ := charles.CreateInvitation(charlesFile, "bob")
			malloryInvite, _ := userlib.DatastoreGet(malloryInvitePtr)
			userlib.DebugMsg("Mallory places his invitation at the address of alice's invitiation")
			userlib.DatastoreSet(invite, []byte(malloryInvite))
			userlib.DebugMsg("Bob tries to accept alice's invitation, which now contains Mallory's invite")
			err = bob.AcceptInvitation("alice", invite, bobFile+"2")
			Expect(err).ToNot(BeNil()) //should fail at the signature check

			userlib.DebugMsg("Alice tries with a third file")
			alice.StoreFile(aliceFile+"3", []byte(contentThree))
			prevDatastore := userlib.DatastoreGetMap()
			oldMap := make(map[userlib.UUID][]byte, len(prevDatastore))
			for k := range prevDatastore {
				oldMap[k], _ = userlib.DatastoreGet(k)
			}

			userlib.DebugMsg("Alice shares the third file to bob")
			invite, _ = alice.CreateInvitation(aliceFile+"3", "bob")

			for k := range userlib.DatastoreGetMap() {
				_, kInMap := oldMap[k]
				if !kInMap {
					userlib.DebugMsg("Mallory tries accepting with the newly added UID")
					err = charles.AcceptInvitation("alice", k, "newfile")
					Expect(err).ToNot(BeNil())
					_, err = charles.LoadFile("newfile")
					Expect(err).ToNot(BeNil())
					userlib.DebugMsg("Mallory tries modifying the data at the UID instead")
					userlib.DatastoreSet(k, []byte("malicious content"))
				}
			}

			userlib.DebugMsg("Bob should detect the tampering by Mallory")
			err = bob.AcceptInvitation("alice", invite, bobFile+"4")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice tries again, this time sharing it to bob and doris")
			invite, _ = alice.CreateInvitation(aliceFile+"3", "bob")
			invite2, _ := alice.CreateInvitation(aliceFile+"3", "doris")

			userlib.DebugMsg("Mallory tries to swap the two invitations")
			dorisInvite, ok := userlib.DatastoreGet(invite2)
			Expect(ok).To(BeTrue())
			bobInvite, ok := userlib.DatastoreGet(invite)
			Expect(ok).To(BeTrue())
			userlib.DatastoreSet(invite, dorisInvite)
			userlib.DatastoreSet(invite2, bobInvite)

			userlib.DebugMsg("Bob and Doris should detect the swap tampering")
			err = bob.AcceptInvitation("alice", invite, bobFile+"4")
			Expect(err).ToNot(BeNil())
			err = doris.AcceptInvitation("alice", invite2, dorisFile)

			userlib.DebugMsg("Alice tries again with a different file")
			alice.StoreFile(aliceFile+"2", []byte(contentOne+"2"))
			invite, _ = alice.CreateInvitation(aliceFile+"2", "bob")

			userlib.DebugMsg("Mallory modifies everything on datastore")
			datastore := userlib.DatastoreGetMap()
			for k := range datastore {
				userlib.DatastoreSet(k, userlib.RandomBytes(8))
			}

			err = bob.AcceptInvitation("alice", invite, bobFile+"3")
			Expect(err).ToNot(BeNil())
		})

		Specify("Flag Test: many shared users", func() {
			userlib.DebugMsg("initializing Alice, Bob, Charles, Doris, Eve")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())
			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares to Bob who shares to Charles")
			invite, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			userlib.DebugMsg("bob loaded the file")
			readContent, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal([]byte(contentOne + contentTwo)))
			readContent, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal([]byte(contentOne + contentTwo)))
			err = bob.StoreFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())
			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			readContent, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal([]byte(contentThree + contentTwo)))
			readContent, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal([]byte(contentThree + contentTwo)))
			err = charles.StoreFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = charles.StoreFile(charlesFile, []byte("random"))
			Expect(err).ToNot(BeNil())
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
			err = charles.AppendToFile(charlesFile, []byte("random"))
			Expect(err).ToNot(BeNil())
			err = bob.AppendToFile(bobFile, []byte("random"))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice shares to Bob who shares to Charles who shares to Doris who shares to Eve")
			invite, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())
			invite, err = charles.CreateInvitation(charlesFile, "doris")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("charles", invite, dorisFile)
			Expect(err).To(BeNil())
			invite, err = doris.CreateInvitation(dorisFile, "eve")
			Expect(err).To(BeNil())
			err = eve.AcceptInvitation("doris", invite, eveFile)
			Expect(err).To(BeNil())

			largeContent := userlib.RandomBytes(1600)
			err = eve.StoreFile(eveFile, largeContent)
			Expect(err).To(BeNil())
			userlib.DebugMsg("bob loaded the file")
			readContent, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(largeContent))
			readContent, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(largeContent))
			err = bob.StoreFile(bobFile, largeContent)
			Expect(err).To(BeNil())
			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			readContent, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(append(largeContent, []byte(contentTwo)...)))
			readContent, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(append(largeContent, []byte(contentTwo)...)))
			err = charles.StoreFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())
			readContent, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal([]byte(contentThree)))

			userlib.DebugMsg("alice revokes bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
			_, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())
			_, err = eve.LoadFile(eveFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Flag Test: File sharing with large files and many shared users", func() {
			userlib.DebugMsg("initializing Alice, Bob, Charles, Doris")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice stores and loads a large file")
			largeContent := userlib.RandomBytes(1500)
			err = alice.StoreFile(aliceFile, largeContent)
			Expect(err).To(BeNil())
			readContent, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(largeContent))
			userlib.DebugMsg("Alice appends a large chunk to the large file, then loads it again")
			err = alice.AppendToFile(aliceFile, largeContent)
			Expect(err).To(BeNil())
			readContent, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(append(largeContent, largeContent...)))

			err = alice.StoreFile(aliceFile, largeContent)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares to Bob who shares to Charlie who shares to Doris")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())
			invite, err = charles.CreateInvitation(charlesFile, "doris")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("charles", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("They should all see the same data")
			readContent, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(largeContent))
			readContent, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(largeContent))
			readContent, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(largeContent))

			userlib.DebugMsg("bob appends to the file")
			err = bob.AppendToFile(bobFile, largeContent)
			Expect(err).To(BeNil())

			userlib.DebugMsg("They should all see bob's added content")
			readContent, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(append(largeContent, largeContent...)))
			readContent, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(append(largeContent, largeContent...)))
			readContent, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(append(largeContent, largeContent...)))

			userlib.DebugMsg("charles appends to file")
			err = charles.AppendToFile(charlesFile, largeContent)
			Expect(err).To(BeNil())

			userlib.DebugMsg("They should all see charles's added content")
			readContent, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(append(largeContent, append(largeContent, largeContent...)...)))
			readContent, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(append(largeContent, append(largeContent, largeContent...)...)))
			readContent, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(append(largeContent, append(largeContent, largeContent...)...)))

			userlib.DebugMsg("doris storeFile with new stuff")
			err = doris.StoreFile(dorisFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("They should all see the new file by doris")
			readContent, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal([]byte(contentOne)))
			readContent, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal([]byte(contentOne)))
			readContent, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal([]byte(contentOne)))

			// test with revoke
			userlib.DebugMsg("Alice decides to share the file with Doris as well")
			invite, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).To(BeNil())
			readContent, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal([]byte(contentOne)))

			readContent, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			readContentBob, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal(readContentBob))
			Expect(readContent).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revokes bob's access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Doris should still see the file, while bob and charlie shouldn't")
			readContent, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(readContent).To(Equal([]byte(contentOne)))
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Flag Test: Revoke and Revoked Adversary", func() {
			userlib.DebugMsg("initializing Alice, Bob, Charles, Doris")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice shares a file with Bob")
			alice.StoreFile(aliceFile, []byte(contentOne))
			invite, _ := alice.CreateInvitation(aliceFile, "bob")
			userlib.DebugMsg("Doris tries to accept Alice's invite instead")
			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Bob accepts Alice's invite, and posts the invite at some other uid of his choosing")
			inviteContent, _ := userlib.DatastoreGet(invite)
			copyInvite := uuid.New()
			userlib.DatastoreSet(copyInvite, []byte(inviteContent))
			bob.AcceptInvitation("alice", invite, bobFile)

			userlib.DebugMsg("Alice shares a file with Charles")
			invite, _ = alice.CreateInvitation(aliceFile, "charles")
			userlib.DebugMsg("Charles accepts the invite, and remembers its uid")
			charles.AcceptInvitation("alice", invite, charlesFile)
			charlesInvite := invite

			userlib.DebugMsg("Charles shares a file with Doris")
			invite, _ = charles.CreateInvitation(charlesFile, "doris")
			userlib.DebugMsg("Doris accepts Charles's invite, and remembers its uid")
			err = doris.AcceptInvitation("charles", invite, dorisFile)
			Expect(err).To(BeNil())
			dorisInvite := invite

			data, _ := doris.LoadFile(dorisFile)
			Expect(data).To(Equal([]byte(contentOne)))
			userlib.DebugMsg("Doris appends ContentTwo to the file")
			doris.AppendToFile(dorisFile, []byte(contentTwo))
			data, _ = bob.LoadFile(bobFile)
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Alice revokes Charles's access to aliceFile")
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).To(BeNil())

			// what if charles remembers invitation uid and then tries to accept it again?
			userlib.DebugMsg("Charles tries to regain access via his remembered invite uid")
			err = charles.AcceptInvitation("alice", charlesInvite, charlesFile+"2")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Doris tries to regain access via remembered invite from charles")
			err = doris.AcceptInvitation("charles", dorisInvite, dorisFile+"2")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Doris and Charles try to append to the file")
			err = charles.AppendToFile(charlesFile+"2", []byte(contentThree))
			Expect(err).ToNot(BeNil())
			err = doris.AppendToFile(dorisFile+"2", []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revokes Bob's access to aliceFile")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			// what if bob datastore sets the invitation somewhere else (Creates his own invitation) and then accepts it after revoke?
			userlib.DebugMsg("Bob tries to regain access by accessing the copy invite he posted")
			err = bob.AcceptInvitation("alice", copyInvite, bobFile+"2")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries to load/append to the file")
			_, err = bob.LoadFile(bobFile + "2")
			Expect(err).ToNot(BeNil())
			err = bob.AppendToFile(bobFile+"2", []byte("random"))
			Expect(err).ToNot(BeNil())
		})
	})

	var _ = Describe("Flag tests: Bandwidth", func() {

		Specify("Flag Test: Bandwidth on AppendToFile", func() {

			// Helper function to measure bandwidth of a particular operation
			measureBandwidth := func(probe func()) (bandwidth int) {
				before := userlib.DatastoreGetBandwidth()
				probe()
				after := userlib.DatastoreGetBandwidth()
				return after - before
			}

			userlib.DebugMsg("initializing user with really big username/password")
			username := string(userlib.RandomBytes(1500))
			password := string(userlib.RandomBytes(1500))
			alice, err = client.InitUser(username, password)
			Expect(err).To(BeNil())
			userlib.DebugMsg("user has very big file with very big filename")
			fileName := string(userlib.RandomBytes(1500))
			content := userlib.RandomBytes(2100)
			bw := measureBandwidth(func() {
				err = alice.StoreFile(fileName, content)
				Expect(err).To(BeNil())
			})
			userlib.DebugMsg("Storing big file bandwidth: %d", bw)
			userlib.DebugMsg("Append to file with large data")

			contentSize := len(content)
			var prevBw int
			for k := 0; k < 10; k++ {
				content = userlib.RandomBytes(k * contentSize)
				for i := 1; i <= 10; i++ {
					bw2 := measureBandwidth(func() {
						err = alice.AppendToFile(fileName, content)
						Expect(err).To(BeNil())
					})
					if i == 1 {
						prevBw = bw2
						continue
					} else {
						userlib.DebugMsg("bandwidth from appending on the %dth time: %d", i, bw2)
						Expect(bw2 == prevBw).To(BeTrue())
					}
				}
			}

			// massiveContentSize := 3000
			// massiveContent := userlib.RandomBytes(5*massiveContentSize)
			// bw3 := measureBandwidth(func() {
			// 	err = alice.AppendToFile(fileName, massiveContent)
			// 	Expect(err).To(BeNil())
			// })
			// userlib.DebugMsg("bandwidth from appending massive content: %d", bw3)
			// ok := bw3 < (5*massiveContentSize + bw)
			// Expect(ok).To(BeTrue())

		})
	})
})
