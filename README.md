Used cryptography functions such as block ciphers, RSA key-sharing, and hashing to implement a secure file-sharing system over a simulated insecure, public database.  The userlib import is just an API that implements these cryptographic functions by wrapping the security library calls with more readable userlib library calls, and also provides an abstraction to the insecure database as Datastore (it’s really just a big hash map with the key being a UID and the value being a []byte array). 


#### Design Doc
See this [design doc](https://docs.google.com/document/d/1MSUFj4kxFw4mP2XCQHgHqMbMd7SXjF3-enOg9mh68i0/edit?usp=sharing) for the underlying security design, or read the feature section below. 

#### Security ‘threats’:
Check out [this link](https://fa25.cs161.org/proj2/library/) for a breakdown of the userlib functions. To get a general overview of the project, and to see what the simulated “adversaries” (people trying to obtain user/file information on Datastore) are capable of doing check out the printed logging in the `client/client_test.go` file, which simulates the adversaries’ behavior.

Implementation in `client/client.go` and integration tests in `client_test/client_test.go`

run `go test -v` inside of the `client_test` directory to test. This will run all tests in both `client/client_unittest.go` and `client_test/client_test.go`.

### Cool Features of this project:
- All data, including User objects and file objects, are stored in a "public" file storage Datastore (implemented as part of a built library given by proj starter code). Datastore is essentially a hashmap, the key being a 16-byte UUID, and the value being the data (encrypted)
- Files are stored as a linked list. If a file is _n_ sections long, then the _n’th_ section is the head of the linked list and points to the _n-1’th_ section, etc. This is to make appending to a file not bandwidth dependent. No need to retrieve all _n_ sections of file from Datastore to append to file, just need the tail section == head of linked list.
- File indirection: To access a file, there are 3 sentinel nodes that must be decrypted before accessing the actual file sections.
    1. User sentinel: Private user sentinel that only each user can access. Contains the UID of the group sentinel, and the sym and mac key pair to verify/decrypt it. 1:1 relation between number of files a user has access to (both owned files and files which shared with the user) and number of user sentinels
    2. Group sentinel: Sentinel formed whenever the file owner shares to someone. Contains the UID of the file sentinel and the sym/mac keys. Eg. if A shares to B, A will make a new group sentinel at UID = hash(B.username + A.pw + fileUID). This enables A to find the group sentinel later on by computing the UID again. If A revokes B's access to file, then deleting the group sentinel and changing the File sentinel's keys effectively prevents B from 1. locating the revoked file, because B's user sentinel no longer points to the correct group sentinel, and 2. using the same keys to decrypt the file, because the file sentinel's keys are changed. 1:1 relation between number of group sentinel's and the number of people the owner has directly shared the file with. 
    3. File sentinel. Contains the UID of the file's tail section (last 512 or less bytes of the file content), the sym-mac key pair to verify/decrypt it, and some metadata about the file: the FileUID (unique to each file created) and the file owner's UID. 1:1 relation between number of existing files and number of file sentinels.
- In summary, UserSentinel -> GroupSentinel -> FileSentinel -> _nth_ fileSection -> _n-1th_ fileSection..., where each A -> B means A contains the location of B and the sym/mac key pair to decrypt B
- File sharing tree: One of the requirements was that if A shares AFILE to B, B can share AFILE to anyone else too. Say, B shares to C and D as well, D shares to E, etc. However, if A revoke's B's access to AFILE, C, D, and E should also lose access; that is, any user in the subtree rooted at B will lose access to AFILE. The group sentinel indirection solves this.
  - Suppose A shared AFILE to B, and B now wants to share to C. By design, B can't make a new group sentinel because B is not the owner of the file, (B.userUID != FileSentinel.OwnerUID), so all he can do is pass the location of the group sentinel and the keys to decrypt it to C. C then creates a new User sentinel which contains the keys to decrypting the group sentinel, which he got from B, and sets that User sentinel at a location only C can find. Now C also has access to AFILE, but if A revokes B, C will also lose access by default because C's UserSentinel for AFILE now points to a nonexistent location in Datastore.

