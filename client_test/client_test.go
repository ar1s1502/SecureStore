package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
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
const contentOne = "Bitcoin is Nick's favorite"
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
	// var eve *client.User
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
	// eveFile := "eveFile.txt"
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

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

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

			userlib.DebugMsg("modifying all of datastore...")
			datastore := userlib.DatastoreGetMap()
			for key := range datastore {
				userlib.DatastoreSet(key, userlib.RandomBytes(8))
			}

			userlib.DebugMsg("calling getUser from aliceLaptop after modifying datastore")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("initializing bob and charles")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Clearing datastore...")
			userlib.DatastoreClear()

			userlib.DebugMsg("Calling get user for bob and charles should err")
			_, err := client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())
			_, err = client.GetUser("charles", defaultPassword)
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

			userlib.DebugMsg("Alice and Bob both create a file called " + aliceFile)
			alice.StoreFile(aliceFile, []byte(contentOne))
			bob.StoreFile(aliceFile, []byte(contentTwo))
			userlib.DebugMsg("Alice shares the file to Bob")
			invite, _ := alice.CreateInvitation(aliceFile, "bob")
			userlib.DebugMsg("Bob tries giving the file the name " + aliceFile)
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Mallory tries creating his own invitation, pretending to be alice")
			charles.StoreFile(charlesFile, []byte(contentThree))
			malloryInvitePtr, _ := charles.CreateInvitation(charlesFile, "bob")
			malloryInvite, _ := userlib.DatastoreGet(malloryInvitePtr)
			userlib.DebugMsg("Mallory places his invitation at the address of alice's invitiation")
			userlib.DatastoreSet(invite, []byte(malloryInvite))
			userlib.DebugMsg("Bob tries to accept alice's invitation, which now contains Mallory's invite")
			err = bob.AcceptInvitation("alice", invite, bobFile+"2")
			Expect(err).ToNot(BeNil()) //should fail at the signature check

			userlib.DebugMsg("Alice tries again with a different file")
			alice.StoreFile(aliceFile+"2", []byte(contentOne+"2"))
			invite, _ = alice.CreateInvitation(aliceFile+"2", "bob")

			userlib.DebugMsg("Mallory modifies everything on datastore")
			datastore := userlib.DatastoreGetMap()
			for k := range datastore {
				userlib.DatastoreSet(k, userlib.RandomBytes(8))
			}

			err = bob.AcceptInvitation("alice", invite, bobFile+"3")
			Expect(err).To(BeNil())

		})

		Specify("Flag Test: Revoke and Revoked Adversary", func() {
			userlib.DebugMsg("initializing Alice, Bob, Charles")
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
			Expect(err).To(BeNil())
			err = doris.AppendToFile(dorisFile+"2", []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes Bob's access to aliceFile")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			// what if bob datastore sets the invitation somewhere else (Creates his own invitation) and then accepts it after revoke?
			userlib.DebugMsg("Bob tries to regain access by accessing the copy invite he posted")
			err = bob.AcceptInvitation("alice", copyInvite, bobFile+"2")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries to load the file")
			_, err = bob.LoadFile(bobFile + "2")
			Expect(err).ToNot(BeNil())
		})
	})
})
