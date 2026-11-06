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
	_ "strings"

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

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).

	PrivateDecKey userlib.PKEDecKey
	PrivateSignKey userlib.DSSignKey
	NamespaceKey []byte
}

type StoredUser struct{
	Salt []byte
	EncryptedData []byte
	Mac []byte
}

type StoredFile struct{
	EncryptedData []byte
	Mac []byte
}

type FileMetadata struct{
	FirstChunk uuid.UUID
	LastChunk uuid.UUID
	FileKey []byte
}

type FileChunk struct{
	Content []byte
	NextChunk uuid.UUID
}

type FileReference struct{
	MetadataUUID uuid.UUID
	MetadataKey []byte
	Owner string
	SharingUUID uuid.UUID
}

type NamespaceEntry struct{
	ReferenceUUID uuid.UUID
	ReferenceKey []byte
}

type StoredReference struct{
	EncryptedData []byte
	Mac []byte
}

type ShareInfo struct{
	Username string
	Parent string
	ReferenceUUID uuid.UUID
	ReferenceKey []byte
}

type SharingNode struct{
	Username string
	Children []ShareInfo
}

type StoredSharingNode struct{
	Encrypted []byte
	Mac []byte
}

type SharingData struct{
	Users []ShareInfo
}

type SharingRecord struct{
	Users []ShareInfo
}

type StoredSharingRecord struct{
	EncryptedData []byte
	Mac []byte
}

type Invitation struct{
	Sender string
	Recipient string
	ReferenceUUID uuid.UUID
	ReferenceKey []byte
}

type StoredInvitation struct{
	EncryptedKey []byte
	EncryptedData []byte
	Mac []byte
	Signature []byte
}
// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		return nil, errors.New("username is empty")
	}

	usernameBytes := []byte(username)
	hashInput := append([]byte("user:"), usernameBytes...)
	hashedUsername := userlib.Hash(hashInput)
	userUUID, err := uuid.FromBytes(hashedUsername[:16])

	if err != nil {
		return nil, err
	}

	data, exists := userlib.DatastoreGet(userUUID)

	if exists {
		return nil, errors.New("user already exists")
	}

	_ = data
	publicKey, privateKey, err := userlib.PKEKeyGen()

	if err != nil{
		return nil, err
	}

	signKey, verifyKey, err := userlib.DSKeyGen()

	if err != nil{
		return nil, err
	}

	randomKey := userlib.RandomBytes(16)

	var userdata User
	userdata.Username = username
	userdata.PrivateDecKey = privateKey
	userdata.PrivateSignKey = signKey
	userdata.NamespaceKey = randomKey
	_ = publicKey
	_ = verifyKey
	_ = password

	//salt
	salt := userlib.RandomBytes(16)
	passwordKey := userlib.Argon2Key([]byte(password), salt, 16)
	encKeyBytes, err := userlib.HashKDF(passwordKey, []byte("encryption"))

	if err != nil{
		return nil, err
	}
	macKeyBytes, err := userlib.HashKDF(passwordKey, []byte("authentication"))

	if err != nil{
		return nil, err
	}

	encKey := encKeyBytes[:16]
	macKey := macKeyBytes[:16]
	userBytes, err := json.Marshal(userdata)

	if err != nil{
		return nil, err
	}

	iv := userlib.RandomBytes(16)
	encryptedUser := userlib.SymEnc(encKey, iv, userBytes)
	mac, err := userlib.HMACEval(macKey, encryptedUser)

	if err != nil{
		return nil, err
	}

	var storedUser StoredUser

	storedUser.Salt = salt
	storedUser.EncryptedData = encryptedUser
	storedUser.Mac = mac

	storedBytes, err := json.Marshal(storedUser)

	if err != nil{
		return nil, err
	}

	userlib.DatastoreSet(userUUID, storedBytes)
	err = userlib.KeystoreSet(username + "_enc", publicKey)

	if err != nil{
		return nil, err
	}

	err = userlib.KeystoreSet(username + "_verify", verifyKey)

	if err != nil {
		return nil, err
	}

	return &userdata, nil


}

func GetUser(username string, password string) (userdataptr *User, err error) {
	
	if username == "" {
		return nil, errors.New("username is empty")
	}

	usernameBytes := []byte(username)
	hashInput := append([]byte("user:"), usernameBytes...)
	hashedUsername := userlib.Hash(hashInput)
	userUUID, err := uuid.FromBytes(hashedUsername[:16])

	if err != nil{
		return nil, err
	}

	storedBytes, exists := userlib.DatastoreGet(userUUID)

	if !exists {
		return nil, errors.New("user does not exist")
	}

	var storedUser StoredUser
	
	err = json.Unmarshal(storedBytes, &storedUser)

	if err != nil{
		return nil, err
	}

	salt := storedUser.Salt

	if len(salt) != 16 {
		return nil, errors.New("invalid set")
	}

	passwordKey := userlib.Argon2Key([]byte(password), salt, 16)
	encKeyBytes, err := userlib.HashKDF(passwordKey, []byte("encryption"))

	if err != nil {
		return nil, err
	}

	macKeyBytes, err := userlib.HashKDF(passwordKey, []byte("authentication"))

	if err != nil{
		return nil, err
	}

	encKey := encKeyBytes[:16]
	macKey := macKeyBytes[:16]

	expectedMac, err := userlib.HMACEval(macKey, storedUser.EncryptedData)

	if err != nil{
		return nil, err
	}

	valid := userlib.HMACEqual(expectedMac, storedUser.Mac)

	if !valid{
		return nil, errors.New("incorrect password or modified user data")
	}

	if len(storedUser.EncryptedData) < 16{
		return nil, errors.New("invalid encrypted data")
	}

	decryptedBytes := userlib.SymDec(encKey, storedUser.EncryptedData)
	
	var userdata User

	err = json.Unmarshal(decryptedBytes, &userdata)

	if err != nil{
		return nil, err
	}

	if userdata.Username != username{
		return nil, errors.New("username does not match")
	}

	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	filenameKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("filename:" + filename),
	)

	if err != nil{
		return err
	}

	fileUUID, err := uuid.FromBytes(filenameKeyBytes[:16])

	if err != nil{
		return err
	}

	_, exists := userlib.DatastoreGet(fileUUID)

	if exists{
		_, err = userdata.LoadFile(filename)

		if err != nil{
			return err
		}

		return userdata.overwriteFile(filename, content)
	}

	

	fileKey := userlib.RandomBytes(16)
	firstChunkUUID := uuid.New()

	var firstChunk FileChunk

	firstChunk.Content = content
	firstChunk.NextChunk = uuid.Nil
	chunkBytes, err := json.Marshal(firstChunk)

	if err != nil{
		return err
	}
	chunkEncKeyBytes, err := userlib.HashKDF(fileKey, []byte("chunk encryption"))

	if err != nil{
		return err
	}

	chunkMacKeyBytes, err := userlib.HashKDF(fileKey, []byte("chunk authentication"))

	if err != nil{
		return err
	}

	chunkEncKey := chunkEncKeyBytes[:16]
	chunkMacKey := chunkMacKeyBytes[:16]
	iv := userlib.RandomBytes(16)
	encryptedChunk := userlib.SymEnc(chunkEncKey, iv, chunkBytes)
	chunkMac, err := userlib.HMACEval(chunkMacKey, encryptedChunk)

	if err != nil{
		return err
	}


	var storedChunk StoredFile

	storedChunk.EncryptedData = encryptedChunk
	storedChunk.Mac = chunkMac
	storedChunkBytes, err := json.Marshal(storedChunk)

	if err != nil{
		return err
	}

	userlib.DatastoreSet(firstChunkUUID, storedChunkBytes)
	var metadata FileMetadata

	metadata.FirstChunk = firstChunkUUID
	metadata.LastChunk = firstChunkUUID
	metadata.FileKey = fileKey
	metadataBytes, err := json.Marshal(metadata)

	if err != nil {
		return err
	}

	metadataKey := userlib.RandomBytes(16)
	metadataUUID := uuid.New()

	metadataEncKeyBytes, err := userlib.HashKDF(metadataKey, []byte("metadata encryption"))

	if err != nil{
		return err
	}

	metadataMacKeyBytes, err := userlib.HashKDF(metadataKey, []byte("metadata authentication"))

	if err != nil{
		return err
	}

	metadataEncKey := metadataEncKeyBytes[:16]
	metadataMacKey := metadataMacKeyBytes[:16]
	metadataIV := userlib.RandomBytes(16)
	encryptedMetadata := userlib.SymEnc(metadataEncKey, metadataIV, metadataBytes)
	metadataMac, err := userlib.HMACEval(metadataMacKey, encryptedMetadata)

	if err != nil{
		return err
	}

	var storedMetadata StoredFile
	storedMetadata.EncryptedData = encryptedMetadata
	storedMetadata.Mac = metadataMac
	storedMetadataBytes, err := json.Marshal(storedMetadata)

	if err != nil{
		return err
	}

	userlib.DatastoreSet(metadataUUID, storedMetadataBytes)

	var fileReference FileReference

	fileReference.MetadataUUID = metadataUUID
	fileReference.MetadataKey = metadataKey
	fileReference.Owner = userdata.Username
	referenceBytes, err := json.Marshal(fileReference)

	if err != nil{
		return err
	}

	referenceUUID := uuid.New()
	referenceKey := userlib.RandomBytes(16)
	referenceEncKeyBytes, err := userlib.HashKDF(
		referenceKey,
		[]byte("reference encryption"),
	)

	if err != nil{
		return err
	}

	referenceMacKeyBytes, err := userlib.HashKDF(
		referenceKey,
		[]byte("reference authentication"),
	)

	if err != nil{
		return err
	}

	referenceEncKey := referenceEncKeyBytes[:16]
	referenceMacKey := referenceMacKeyBytes[:16]

	referenceIV := userlib.RandomBytes(16)

	encryptedReference := userlib.SymEnc(
		referenceEncKey,
		referenceIV,
		referenceBytes,
	)

	referenceMac, err := userlib.HMACEval(
		referenceMacKey,
		encryptedReference,
	)

	if err != nil {
		return err
	}

	var storedReference StoredReference

	storedReference.EncryptedData = encryptedReference
	storedReference.Mac = referenceMac

	storedReferenceBytes, err := json.Marshal(storedReference)

	if err != nil {
		return err
	}

	userlib.DatastoreSet(referenceUUID, storedReferenceBytes)

	var namespaceEntry NamespaceEntry

	namespaceEntry.ReferenceUUID = referenceUUID
	namespaceEntry.ReferenceKey = referenceKey

	namespaceBytes, err := json.Marshal(namespaceEntry)

	if err != nil {
		return err
	}

	namespaceEncKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("namespace encryption:" + filename),
	)

	if err != nil {
		return err
	}

	namespaceMacKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("namespace authentication:" + filename),
	)

	if err != nil {
		return err
	}

	namespaceEncKey := namespaceEncKeyBytes[:16]
	namespaceMacKey := namespaceMacKeyBytes[:16]

	namespaceIV := userlib.RandomBytes(16)

	encryptedNamespace := userlib.SymEnc(
		namespaceEncKey,
		namespaceIV,
		namespaceBytes,
	)

	namespaceMac, err := userlib.HMACEval(
		namespaceMacKey,
		encryptedNamespace,
	)

	if err != nil {
		return err
	}

	var storedNamespace StoredFile

	storedNamespace.EncryptedData = encryptedNamespace
	storedNamespace.Mac = namespaceMac

	storedNamespaceBytes, err := json.Marshal(storedNamespace)

	if err != nil {
		return err
	}

	userlib.DatastoreSet(fileUUID, storedNamespaceBytes)

	sharingUUIDBytes, err := userlib.HashKDF(
	userdata.NamespaceKey,
	[]byte("sharing uuid:" + filename),
	)
	if err != nil {
		return err
	}

	sharingUUID, err := uuid.FromBytes(sharingUUIDBytes[:16])
	if err != nil {
		return err
	}

	sharingKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("sharing key:" + filename),
	)
	if err != nil {
		return err
	}

	sharingKey := sharingKeyBytes[:16]

	var sharingRecord SharingRecord
	sharingRecord.Users = make([]ShareInfo, 0)

	sharingBytes, err := json.Marshal(sharingRecord)
	if err != nil {
		return err
	}

	sharingEncKey, sharingMacKey, err := getSharingKeys(sharingKey)
	if err != nil {
		return err
	}

	sharingIV := userlib.RandomBytes(16)

	encryptedSharing := userlib.SymEnc(
		sharingEncKey,
		sharingIV,
		sharingBytes,
	)

	sharingMac, err := userlib.HMACEval(
		sharingMacKey,
		encryptedSharing,
	)
	if err != nil {
		return err
	}

	var storedSharing StoredSharingRecord
	storedSharing.EncryptedData = encryptedSharing
	storedSharing.Mac = sharingMac

	storedSharingBytes, err := json.Marshal(storedSharing)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(sharingUUID, storedSharingBytes)
		return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	filenameKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("filename:" + filename),
	)

	if err != nil{
		return errors.New("invalid file data")
	}

	fileUUID, err := uuid.FromBytes(filenameKeyBytes[:16])

	if err != nil{
		return err
	}

	storedNamespaceBytes, exists := userlib.DatastoreGet(fileUUID)
	if !exists{
		return errors.New("file does note exist")
	}

	var storedNamespace StoredFile
    err = json.Unmarshal(storedNamespaceBytes, &storedNamespace)
    if err != nil {
        return err
    }

    namespaceEncKeyBytes, err := userlib.HashKDF(
        userdata.NamespaceKey,
        []byte("namespace encryption:" + filename),
    )

    if err != nil {
        return err
    }

    namespaceMacKeyBytes, err := userlib.HashKDF(
        userdata.NamespaceKey,
        []byte("namespace authentication:" + filename),
    )

    if err != nil {
        return err
    }

    namespaceEncKey := namespaceEncKeyBytes[:16]
    namespaceMacKey := namespaceMacKeyBytes[:16]

    expectedNamespaceMac, err := userlib.HMACEval(
        namespaceMacKey,
        storedNamespace.EncryptedData,
    )

    if err != nil {
        return err
    }

    if !userlib.HMACEqual(expectedNamespaceMac, storedNamespace.Mac) {
        return errors.New("namespace was modified")
    }

    if len(storedNamespace.EncryptedData) < 16 {
        return errors.New("invalid namespace")
    }

    namespaceBytes := userlib.SymDec(
        namespaceEncKey,
        storedNamespace.EncryptedData,
    )

    var namespaceEntry NamespaceEntry

    err = json.Unmarshal(namespaceBytes, &namespaceEntry)

    if err != nil {
        return err
    }
	
	//get file ref
	    storedReferenceBytes, exists := userlib.DatastoreGet(
        namespaceEntry.ReferenceUUID,
    )

    if !exists {
        return errors.New("file reference does not exist")
    }

    var storedReference StoredReference

    err = json.Unmarshal(storedReferenceBytes, &storedReference)

    if err != nil {
        return err
    }

    referenceEncKeyBytes, err := userlib.HashKDF(
        namespaceEntry.ReferenceKey,
        []byte("reference encryption"),
    )

    if err != nil {
        return err
    }

    referenceMacKeyBytes, err := userlib.HashKDF(
        namespaceEntry.ReferenceKey,
        []byte("reference authentication"),
    )

    if err != nil {
        return err
    }

    referenceEncKey := referenceEncKeyBytes[:16]
    referenceMacKey := referenceMacKeyBytes[:16]

    expectedReferenceMac, err := userlib.HMACEval(
        referenceMacKey,
        storedReference.EncryptedData,
    )

    if err != nil {
        return err
    }

    if !userlib.HMACEqual(expectedReferenceMac, storedReference.Mac) {
        return errors.New("file reference was modified")
    }

    if len(storedReference.EncryptedData) < 16 {
        return errors.New("invalid file reference")
    }

    referenceBytes := userlib.SymDec(
        referenceEncKey,
        storedReference.EncryptedData,
    )

    var fileReference FileReference

    err = json.Unmarshal(referenceBytes, &fileReference)

    if err != nil {
        return err
    }
    storedMetadataBytes, exists := userlib.DatastoreGet(
        fileReference.MetadataUUID,
    )

    if !exists {
        return errors.New("file metadata does not exist")
    }

    var storedMetadata StoredFile

    err = json.Unmarshal(storedMetadataBytes, &storedMetadata)

    if err != nil {
        return err
    }

    metadataEncKeyBytes, err := userlib.HashKDF(
        fileReference.MetadataKey,
        []byte("metadata encryption"),
    )

    if err != nil {
        return err
    }

    metadataMacKeyBytes, err := userlib.HashKDF(
        fileReference.MetadataKey,
        []byte("metadata authentication"),
    )

    if err != nil {
        return err
    }

    metadataEncKey := metadataEncKeyBytes[:16]
    metadataMacKey := metadataMacKeyBytes[:16]

    expectedMetadataMac, err := userlib.HMACEval(
        metadataMacKey,
        storedMetadata.EncryptedData,
    )

    if err != nil {
        return err
    }

    if !userlib.HMACEqual(expectedMetadataMac, storedMetadata.Mac) {
        return errors.New("file metadata was modified")
    }

    if len(storedMetadata.EncryptedData) < 16 {
        return errors.New("invalid file metadata")
    }

    metadataBytes := userlib.SymDec(
        metadataEncKey,
        storedMetadata.EncryptedData,
    )

    var metadata FileMetadata

    err = json.Unmarshal(metadataBytes, &metadata)

    if err != nil {
        return err
    }

    if len(metadata.FileKey) != 16 {
        return errors.New("invalid file key")
    }

    if metadata.FirstChunk == uuid.Nil || metadata.LastChunk == uuid.Nil {
        return errors.New("invalid file chunks")
    }
	chunkEncKeyBytes, err := userlib.HashKDF(metadata.FileKey, []byte("chunk encryption"))

	if err != nil{
		return err
	}

	chunkMacKeyBytes, err := userlib.HashKDF(metadata.FileKey, []byte("chunk authentication"))
	if err != nil{
		return err
	}

	chunkEncKey := chunkEncKeyBytes[:16]
	chunkMacKey := chunkMacKeyBytes[:16]
	lastChunkUUID := metadata.LastChunk
	lastChunkBytes, exists := userlib.DatastoreGet(lastChunkUUID)

	if !exists{
		return errors.New("last chunk does not exist")
	}

	var storedLastChunk StoredFile
	err = json.Unmarshal(lastChunkBytes, &storedLastChunk)

	if err != nil{
		return err
	}

	lastChunkMac, err := userlib.HMACEval(chunkMacKey, storedLastChunk.EncryptedData)

	if err != nil{
		return err
	}

	if !userlib.HMACEqual(lastChunkMac, storedLastChunk.Mac){
		return errors.New("last chunk was modified")
	}

	if len(storedLastChunk.EncryptedData) < 16{
		return errors.New("invalid last chunk")
	}

	lastChunkPlaintext := userlib.SymDec(chunkEncKey, storedLastChunk.EncryptedData)

	var lastChunk FileChunk

	err = json.Unmarshal(lastChunkPlaintext, &lastChunk)

	if err != nil{
		return err
	}

	if lastChunk.NextChunk != uuid.Nil{
		return errors.New("invalid last chunk pointer")
	}

	//new chunk
	newChunkUUID := uuid.New()
	var newChunk FileChunk
	newChunk.Content = content
	newChunk.NextChunk = uuid.Nil
	newChunkBytes, err := json.Marshal(newChunk)

	if err != nil{
		return err
	}

	newIV := userlib.RandomBytes(16)
	encryptedNewChunk := userlib.SymEnc(chunkEncKey, newIV, newChunkBytes)
	newChunkMac, err := userlib.HMACEval(chunkMacKey, encryptedNewChunk)

	if err != nil{
		return err
	}

	var storedNewChunk StoredFile
	storedNewChunk.EncryptedData = encryptedNewChunk
	storedNewChunk.Mac = newChunkMac
	storedNewChunkBytes, err := json.Marshal(storedNewChunk)

	if err != nil{
		return err
	}

	lastChunk.NextChunk = newChunkUUID
	updatedLastChunkBytes, err := json.Marshal(lastChunk)
	if err != nil{
		return err
	}

	updatedIV := userlib.RandomBytes(16)
	encryptedLastChunk := userlib.SymEnc(chunkEncKey, updatedIV, updatedLastChunkBytes)
	updatedLastMac, err := userlib.HMACEval(chunkMacKey, encryptedLastChunk)

	if err != nil{
		return err
	}

	storedLastChunk.EncryptedData = encryptedLastChunk
	storedLastChunk.Mac = updatedLastMac
	updatedStoredLastBytes, err := json.Marshal(storedLastChunk)
	if err != nil{
		return err
	}

	metadata.LastChunk = newChunkUUID
	updatedMetadataBytes, err := json.Marshal(metadata)
	if err != nil{
		return err
	}

	metadataIV := userlib.RandomBytes(16)
	encryptedMetadata := userlib.SymEnc(metadataEncKey, metadataIV, updatedMetadataBytes)
	updatedMetadataMac, err := userlib.HMACEval(metadataMacKey, encryptedMetadata)

	if err != nil{
		return err
	}

	storedMetadata.EncryptedData = encryptedMetadata
	storedMetadata.Mac = updatedMetadataMac
	updatedStoredMetadataBytes, err := json.Marshal(storedMetadata)
	if err != nil{
		return err
	}

	userlib.DatastoreSet(newChunkUUID, storedNewChunkBytes)
	userlib.DatastoreSet(lastChunkUUID, updatedStoredLastBytes)
	userlib.DatastoreSet(fileReference.MetadataUUID, updatedStoredMetadataBytes)

	return nil
}

func (userdata *User) overwriteFile(filename string, content []byte) error{
	filenameKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("filename:" + filename),
	)

	if err != nil{
		return errors.New("invalid file data")
	}

	fileUUID, err := uuid.FromBytes(filenameKeyBytes[:16])

	if err != nil{
		return err
	}

	storedNamespaceBytes, exists := userlib.DatastoreGet(fileUUID)
	if !exists{
		return errors.New("file does note exist")
	}

	var storedNamespace StoredFile
    err = json.Unmarshal(storedNamespaceBytes, &storedNamespace)
    if err != nil {
        return err
    }

    namespaceEncKeyBytes, err := userlib.HashKDF(
        userdata.NamespaceKey,
        []byte("namespace encryption:" + filename),
    )

    if err != nil {
        return err
    }

    namespaceMacKeyBytes, err := userlib.HashKDF(
        userdata.NamespaceKey,
        []byte("namespace authentication:" + filename),
    )

    if err != nil {
        return err
    }

    namespaceEncKey := namespaceEncKeyBytes[:16]
    namespaceMacKey := namespaceMacKeyBytes[:16]

    expectedNamespaceMac, err := userlib.HMACEval(
        namespaceMacKey,
        storedNamespace.EncryptedData,
    )

    if err != nil {
        return err
    }

    if !userlib.HMACEqual(expectedNamespaceMac, storedNamespace.Mac) {
        return errors.New("namespace was modified")
    }

    if len(storedNamespace.EncryptedData) < 16 {
        return errors.New("invalid namespace")
    }

    namespaceBytes := userlib.SymDec(
        namespaceEncKey,
        storedNamespace.EncryptedData,
    )

    var namespaceEntry NamespaceEntry

    err = json.Unmarshal(namespaceBytes, &namespaceEntry)

    if err != nil {
        return err
    }
	
	//get file ref
	    storedReferenceBytes, exists := userlib.DatastoreGet(
        namespaceEntry.ReferenceUUID,
    )

    if !exists {
        return errors.New("file reference does not exist")
    }

    var storedReference StoredReference

    err = json.Unmarshal(storedReferenceBytes, &storedReference)

    if err != nil {
        return err
    }

    referenceEncKeyBytes, err := userlib.HashKDF(
        namespaceEntry.ReferenceKey,
        []byte("reference encryption"),
    )

    if err != nil {
        return err
    }

    referenceMacKeyBytes, err := userlib.HashKDF(
        namespaceEntry.ReferenceKey,
        []byte("reference authentication"),
    )

    if err != nil {
        return err
    }

    referenceEncKey := referenceEncKeyBytes[:16]
    referenceMacKey := referenceMacKeyBytes[:16]

    expectedReferenceMac, err := userlib.HMACEval(
        referenceMacKey,
        storedReference.EncryptedData,
    )

    if err != nil {
        return err
    }

    if !userlib.HMACEqual(expectedReferenceMac, storedReference.Mac) {
        return errors.New("file reference was modified")
    }

    if len(storedReference.EncryptedData) < 16 {
        return errors.New("invalid file reference")
    }

    referenceBytes := userlib.SymDec(
        referenceEncKey,
        storedReference.EncryptedData,
    )

    var fileReference FileReference

    err = json.Unmarshal(referenceBytes, &fileReference)

    if err != nil {
        return err
    }
    storedMetadataBytes, exists := userlib.DatastoreGet(
        fileReference.MetadataUUID,
    )

    if !exists {
        return errors.New("file metadata does not exist")
    }

    var storedMetadata StoredFile

    err = json.Unmarshal(storedMetadataBytes, &storedMetadata)

    if err != nil {
        return err
    }

    metadataEncKeyBytes, err := userlib.HashKDF(
        fileReference.MetadataKey,
        []byte("metadata encryption"),
    )

    if err != nil {
        return err
    }

    metadataMacKeyBytes, err := userlib.HashKDF(
        fileReference.MetadataKey,
        []byte("metadata authentication"),
    )

    if err != nil {
        return err
    }

    metadataEncKey := metadataEncKeyBytes[:16]
    metadataMacKey := metadataMacKeyBytes[:16]

    expectedMetadataMac, err := userlib.HMACEval(
        metadataMacKey,
        storedMetadata.EncryptedData,
    )

    if err != nil {
        return err
    }

    if !userlib.HMACEqual(expectedMetadataMac, storedMetadata.Mac) {
        return errors.New("file metadata was modified")
    }

    if len(storedMetadata.EncryptedData) < 16 {
        return errors.New("invalid file metadata")
    }

    metadataBytes := userlib.SymDec(
        metadataEncKey,
        storedMetadata.EncryptedData,
    )

    var metadata FileMetadata

    err = json.Unmarshal(metadataBytes, &metadata)

    if err != nil {
        return err
    }

    if len(metadata.FileKey) != 16 {
        return errors.New("invalid file key")
    }

    if metadata.FirstChunk == uuid.Nil || metadata.LastChunk == uuid.Nil {
        return errors.New("invalid file chunks")
    }
	
	//replacement chunk
    chunkEncKeyBytes, err := userlib.HashKDF(
        metadata.FileKey,
        []byte("chunk encryption"),
    )

    if err != nil {
        return err
    }

    chunkMacKeyBytes, err := userlib.HashKDF(
        metadata.FileKey,
        []byte("chunk authentication"),
    )

    if err != nil {
        return err
    }

    chunkEncKey := chunkEncKeyBytes[:16]
    chunkMacKey := chunkMacKeyBytes[:16]

    newChunkUUID := uuid.New()

    var newChunk FileChunk
    newChunk.Content = content
    newChunk.NextChunk = uuid.Nil

    newChunkBytes, err := json.Marshal(newChunk)

    if err != nil {
        return err
    }

    newIV := userlib.RandomBytes(16)

    encryptedNewChunk := userlib.SymEnc(
        chunkEncKey,
        newIV,
        newChunkBytes,
    )

    newChunkMac, err := userlib.HMACEval(
        chunkMacKey,
        encryptedNewChunk,
    )

    if err != nil {
        return err
    }

    var storedNewChunk StoredFile
    storedNewChunk.EncryptedData = encryptedNewChunk
    storedNewChunk.Mac = newChunkMac

    storedNewChunkBytes, err := json.Marshal(storedNewChunk)

    if err != nil {
        return err
    }
	
    metadata.FirstChunk = newChunkUUID
    metadata.LastChunk = newChunkUUID

    updatedMetadataBytes, err := json.Marshal(metadata)

    if err != nil {
        return err
    }

    metadataIV := userlib.RandomBytes(16)

    encryptedMetadata := userlib.SymEnc(
        metadataEncKey,
        metadataIV,
        updatedMetadataBytes,
    )

    updatedMetadataMac, err := userlib.HMACEval(
        metadataMacKey,
        encryptedMetadata,
    )

    if err != nil {
        return err
    }

    storedMetadata.EncryptedData = encryptedMetadata
    storedMetadata.Mac = updatedMetadataMac

    updatedStoredMetadataBytes, err := json.Marshal(storedMetadata)

    if err != nil {
        return err
    }
    userlib.DatastoreSet(newChunkUUID, storedNewChunkBytes)

    // Update the original metadata location
    userlib.DatastoreSet(
        fileReference.MetadataUUID,
        updatedStoredMetadataBytes,
    )

    return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	filenameKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("filename:" + filename),
	)

	if err != nil{
		return nil, errors.New("invalid file data")
	}

	fileUUID, err := uuid.FromBytes(filenameKeyBytes[:16])

	if err != nil{
		return nil, err
	}

	storedNamespaceBytes, exists := userlib.DatastoreGet(fileUUID)
	if !exists{
		return nil, errors.New("file does note exist")
	}

	var storedNamespace StoredFile
    err = json.Unmarshal(storedNamespaceBytes, &storedNamespace)
    if err != nil {
        return nil, err
    }

    namespaceEncKeyBytes, err := userlib.HashKDF(
        userdata.NamespaceKey,
        []byte("namespace encryption:" + filename),
    )

    if err != nil {
        return nil, err
    }

    namespaceMacKeyBytes, err := userlib.HashKDF(
        userdata.NamespaceKey,
        []byte("namespace authentication:" + filename),
    )

    if err != nil {
        return nil, err
    }

    namespaceEncKey := namespaceEncKeyBytes[:16]
    namespaceMacKey := namespaceMacKeyBytes[:16]

    expectedNamespaceMac, err := userlib.HMACEval(
        namespaceMacKey,
        storedNamespace.EncryptedData,
    )

    if err != nil {
        return nil, err
    }

    if !userlib.HMACEqual(expectedNamespaceMac, storedNamespace.Mac) {
        return nil, errors.New("namespace was modified")
    }

    if len(storedNamespace.EncryptedData) < 16 {
        return nil, errors.New("invalid namespace")
    }

    namespaceBytes := userlib.SymDec(
        namespaceEncKey,
        storedNamespace.EncryptedData,
    )

    var namespaceEntry NamespaceEntry

    err = json.Unmarshal(namespaceBytes, &namespaceEntry)

    if err != nil {
        return nil, err
    }
	
	//get file ref
	    storedReferenceBytes, exists := userlib.DatastoreGet(
        namespaceEntry.ReferenceUUID,
    )

    if !exists {
        return nil, errors.New("file reference does not exist")
    }

    var storedReference StoredReference

    err = json.Unmarshal(storedReferenceBytes, &storedReference)

    if err != nil {
        return nil, err
    }

    referenceEncKeyBytes, err := userlib.HashKDF(
        namespaceEntry.ReferenceKey,
        []byte("reference encryption"),
    )

    if err != nil {
        return nil, err
    }

    referenceMacKeyBytes, err := userlib.HashKDF(
        namespaceEntry.ReferenceKey,
        []byte("reference authentication"),
    )

    if err != nil {
        return nil, err
    }

    referenceEncKey := referenceEncKeyBytes[:16]
    referenceMacKey := referenceMacKeyBytes[:16]

    expectedReferenceMac, err := userlib.HMACEval(
        referenceMacKey,
        storedReference.EncryptedData,
    )

    if err != nil {
        return nil, err
    }

    if !userlib.HMACEqual(expectedReferenceMac, storedReference.Mac) {
        return nil, errors.New("file reference was modified")
    }

    if len(storedReference.EncryptedData) < 16 {
        return nil, errors.New("invalid file reference")
    }

    referenceBytes := userlib.SymDec(
        referenceEncKey,
        storedReference.EncryptedData,
    )

    var fileReference FileReference

    err = json.Unmarshal(referenceBytes, &fileReference)

    if err != nil {
        return nil, err
    }
    storedMetadataBytes, exists := userlib.DatastoreGet(
        fileReference.MetadataUUID,
    )

    if !exists {
        return nil, errors.New("file metadata does not exist")
    }

    var storedMetadata StoredFile

    err = json.Unmarshal(storedMetadataBytes, &storedMetadata)

    if err != nil {
        return nil, err
    }

    metadataEncKeyBytes, err := userlib.HashKDF(
        fileReference.MetadataKey,
        []byte("metadata encryption"),
    )

    if err != nil {
        return nil, err
    }

    metadataMacKeyBytes, err := userlib.HashKDF(
        fileReference.MetadataKey,
        []byte("metadata authentication"),
    )

    if err != nil {
        return nil, err
    }

    metadataEncKey := metadataEncKeyBytes[:16]
    metadataMacKey := metadataMacKeyBytes[:16]

    expectedMetadataMac, err := userlib.HMACEval(
        metadataMacKey,
        storedMetadata.EncryptedData,
    )

    if err != nil {
        return nil, err
    }

    if !userlib.HMACEqual(expectedMetadataMac, storedMetadata.Mac) {
        return nil, errors.New("file metadata was modified")
    }

    if len(storedMetadata.EncryptedData) < 16 {
        return nil, errors.New("invalid file metadata")
    }

    metadataBytes := userlib.SymDec(
        metadataEncKey,
        storedMetadata.EncryptedData,
    )

    var metadata FileMetadata

    err = json.Unmarshal(metadataBytes, &metadata)

    if err != nil {
        return nil, err
    }

    if len(metadata.FileKey) != 16 {
        return nil, errors.New("invalid file key")
    }

    if metadata.FirstChunk == uuid.Nil || metadata.LastChunk == uuid.Nil {
        return nil, errors.New("invalid file chunks")
    }
	chunkEncKeyBytes, err := userlib.HashKDF(metadata.FileKey, []byte("chunk encryption"))
	if err != nil{
		return nil, err
	}

	chunkMacKeyBytes, err := userlib.HashKDF(metadata.FileKey, []byte("chunk authentication"))
	
	if err != nil{
		return nil, err
	}

	chunkEncKey := chunkEncKeyBytes[:16]
	chunkMacKey := chunkMacKeyBytes[:16]
	currentUUID := metadata.FirstChunk
	result := make([]byte, 0)
	visited := make(map[uuid.UUID]bool)

	for currentUUID != uuid.Nil{
		if visited[currentUUID]{
			return nil, errors.New("file contains a cycle")
		}
		visited[currentUUID] = true
		storedChunkBytes, exists := userlib.DatastoreGet(currentUUID)

		if !exists{
			return nil, errors.New("file chunk does not exist")
		}

		var storedChunk StoredFile
		err = json.Unmarshal(storedChunkBytes, &storedChunk)

		if err != nil{
			return nil, err
		}

		expectedChunkMac, err := userlib.HMACEval(chunkMacKey, storedChunk.EncryptedData)

		if err != nil {
			return nil, err
		}

		if !userlib.HMACEqual(expectedChunkMac, storedChunk.Mac){
			return nil, errors.New("file chunk was modified")
		}

		if len(storedChunk.EncryptedData) < 16 {
			return nil, errors.New("invalid file chunk")
		}

		chunkBytes := userlib.SymDec(chunkEncKey, storedChunk.EncryptedData)
		var chunk FileChunk

		err = json.Unmarshal(chunkBytes, &chunk)
		if err != nil{
			return nil, err
		}

		for i := 0; i < len(chunk.Content); i++{
			result = append(result, chunk.Content[i])
		}

		currentUUID = chunk.NextChunk
	}

	return result, nil


}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	recipientPublicKey, exists := userlib.KeystoreGet(recipientUsername + "_enc")
	if !exists {
		return uuid.Nil, errors.New("recipient does not exist")
	}

	_, err = userdata.LoadFile(filename)
	if err != nil {
		return uuid.Nil, err
	}

	filenameKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("filename:" + filename),
	)
	if err != nil {
		return uuid.Nil, err
	}

	fileUUID, err := uuid.FromBytes(filenameKeyBytes[:16])
	if err != nil {
		return uuid.Nil, err
	}

	storedNamespaceBytes, exists := userlib.DatastoreGet(fileUUID)
	if !exists {
		return uuid.Nil, errors.New("file does not exist")
	}

	var storedNamespace StoredFile
	err = json.Unmarshal(storedNamespaceBytes, &storedNamespace)
	if err != nil {
		return uuid.Nil, err
	}

	namespaceEncKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("namespace encryption:" + filename),
	)
	if err != nil {
		return uuid.Nil, err
	}

	namespaceMacKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("namespace authentication:" + filename),
	)
	if err != nil {
		return uuid.Nil, err
	}

	namespaceEncKey := namespaceEncKeyBytes[:16]
	namespaceMacKey := namespaceMacKeyBytes[:16]

	expectedNamespaceMac, err := userlib.HMACEval(
		namespaceMacKey,
		storedNamespace.EncryptedData,
	)
	if err != nil {
		return uuid.Nil, err
	}

	if !userlib.HMACEqual(expectedNamespaceMac, storedNamespace.Mac) {
		return uuid.Nil, errors.New("namespace was modified")
	}

	if len(storedNamespace.EncryptedData) < 16 {
		return uuid.Nil, errors.New("invalid namespace")
	}

	namespaceBytes := userlib.SymDec(
		namespaceEncKey,
		storedNamespace.EncryptedData,
	)

	var namespaceEntry NamespaceEntry
	err = json.Unmarshal(namespaceBytes, &namespaceEntry)
	if err != nil {
		return uuid.Nil, err
	}

	storedReferenceBytes, exists := userlib.DatastoreGet(
		namespaceEntry.ReferenceUUID,
	)
	if !exists {
		return uuid.Nil, errors.New("file reference does not exist")
	}

	var storedReference StoredReference
	err = json.Unmarshal(storedReferenceBytes, &storedReference)
	if err != nil {
		return uuid.Nil, err
	}

	referenceEncKeyBytes, err := userlib.HashKDF(
		namespaceEntry.ReferenceKey,
		[]byte("reference encryption"),
	)
	if err != nil {
		return uuid.Nil, err
	}

	referenceMacKeyBytes, err := userlib.HashKDF(
		namespaceEntry.ReferenceKey,
		[]byte("reference authentication"),
	)
	if err != nil {
		return uuid.Nil, err
	}

	referenceEncKey := referenceEncKeyBytes[:16]
	referenceMacKey := referenceMacKeyBytes[:16]

	expectedReferenceMac, err := userlib.HMACEval(
		referenceMacKey,
		storedReference.EncryptedData,
	)
	if err != nil {
		return uuid.Nil, err
	}

	if !userlib.HMACEqual(expectedReferenceMac, storedReference.Mac) {
		return uuid.Nil, errors.New("file reference was modified")
	}

	if len(storedReference.EncryptedData) < 16 {
		return uuid.Nil, errors.New("invalid file reference")
	}

	referenceBytes := userlib.SymDec(
		referenceEncKey,
		storedReference.EncryptedData,
	)

	var fileReference FileReference
	err = json.Unmarshal(referenceBytes, &fileReference)
	if err != nil {
		return uuid.Nil, err
	}

	recipientReferenceUUID := uuid.New()
	recipientReferenceKey := userlib.RandomBytes(16)

	recipientReference := fileReference

	recipientReferenceBytes, err := json.Marshal(recipientReference)
	if err != nil {
		return uuid.Nil, err
	}

	recipientRefEncKeyBytes, err := userlib.HashKDF(
		recipientReferenceKey,
		[]byte("reference encryption"),
	)
	if err != nil {
		return uuid.Nil, err
	}

	recipientRefMacKeyBytes, err := userlib.HashKDF(
		recipientReferenceKey,
		[]byte("reference authentication"),
	)
	if err != nil {
		return uuid.Nil, err
	}

	recipientRefEncKey := recipientRefEncKeyBytes[:16]
	recipientRefMacKey := recipientRefMacKeyBytes[:16]

	recipientRefIV := userlib.RandomBytes(16)

	encryptedRecipientRef := userlib.SymEnc(
		recipientRefEncKey,
		recipientRefIV,
		recipientReferenceBytes,
	)

	recipientRefMac, err := userlib.HMACEval(
		recipientRefMacKey,
		encryptedRecipientRef,
	)
	if err != nil {
		return uuid.Nil, err
	}

	var storedRecipientReference StoredReference
	storedRecipientReference.EncryptedData = encryptedRecipientRef
	storedRecipientReference.Mac = recipientRefMac

	storedRecipientRefBytes, err := json.Marshal(storedRecipientReference)
	if err != nil {
		return uuid.Nil, err
	}

	var invitation Invitation
	invitation.Sender = userdata.Username
	invitation.Recipient = recipientUsername
	invitation.ReferenceUUID = recipientReferenceUUID
	invitation.ReferenceKey = recipientReferenceKey

	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}

	invitationKey := userlib.RandomBytes(16)

	encryptedInvitationKey, err := userlib.PKEEnc(
		recipientPublicKey,
		invitationKey,
	)
	if err != nil {
		return uuid.Nil, err
	}

	invitationEncKeyBytes, err := userlib.HashKDF(
		invitationKey,
		[]byte("invitation encryption"),
	)
	if err != nil {
		return uuid.Nil, err
	}

	invitationMacKeyBytes, err := userlib.HashKDF(
		invitationKey,
		[]byte("invitation authentication"),
	)
	if err != nil {
		return uuid.Nil, err
	}

	encryptedInvitation := userlib.SymEnc(
		invitationEncKeyBytes[:16],
		userlib.RandomBytes(16),
		invitationBytes,
	)

	invitationMac, err := userlib.HMACEval(
		invitationMacKeyBytes[:16],
		encryptedInvitation,
	)
	if err != nil {
		return uuid.Nil, err
	}

	signedBytes := append(
		append([]byte{}, encryptedInvitationKey...),
		encryptedInvitation...,
	)

	signedBytes = append(signedBytes, invitationMac...)

	invitationSignature, err := userlib.DSSign(
		userdata.PrivateSignKey,
		signedBytes,
	)
	if err != nil {
		return uuid.Nil, err
	}

	var storedInvitation StoredInvitation
	storedInvitation.EncryptedKey = encryptedInvitationKey
	storedInvitation.EncryptedData = encryptedInvitation
	storedInvitation.Mac = invitationMac
	storedInvitation.Signature = invitationSignature

	storedInvitationBytes, err := json.Marshal(storedInvitation)
	if err != nil {
		return uuid.Nil, err
	}

	invitationPtr = uuid.New()

if fileReference.Owner == userdata.Username {
	sharingUUIDBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("sharing uuid:" + filename),
	)
	if err != nil {
		return uuid.Nil, err
	}

	sharingUUID, err := uuid.FromBytes(sharingUUIDBytes[:16])
	if err != nil {
		return uuid.Nil, err
	}

	sharingKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("sharing key:" + filename),
	)
	if err != nil {
		return uuid.Nil, err
	}

	sharingKey := sharingKeyBytes[:16]

	storedSharingBytes, exists := userlib.DatastoreGet(sharingUUID)
	if !exists {
		return uuid.Nil, errors.New("sharing registry does not exist")
	}

	var storedSharing StoredSharingRecord
	err = json.Unmarshal(storedSharingBytes, &storedSharing)
	if err != nil {
		return uuid.Nil, err
	}

	sharingEncKey, sharingMacKey, err := getSharingKeys(sharingKey)
	if err != nil {
		return uuid.Nil, err
	}

	expectedSharingMac, err := userlib.HMACEval(
		sharingMacKey,
		storedSharing.EncryptedData,
	)
	if err != nil {
		return uuid.Nil, err
	}

	if !userlib.HMACEqual(expectedSharingMac, storedSharing.Mac) {
		return uuid.Nil, errors.New("sharing registry was modified")
	}

	if len(storedSharing.EncryptedData) < 16 {
		return uuid.Nil, errors.New("invalid sharing registry")
	}

	sharingBytes := userlib.SymDec(
		sharingEncKey,
		storedSharing.EncryptedData,
	)

	var sharingRecord SharingRecord
	err = json.Unmarshal(sharingBytes, &sharingRecord)
	if err != nil {
		return uuid.Nil, err
	}

	var newShare ShareInfo
	newShare.Username = recipientUsername
	newShare.Parent = userdata.Username
	newShare.ReferenceUUID = recipientReferenceUUID
	newShare.ReferenceKey = recipientReferenceKey

	sharingRecord.Users = append(sharingRecord.Users, newShare)

	updatedSharingBytes, err := json.Marshal(sharingRecord)
	if err != nil {
		return uuid.Nil, err
	}

	encryptedSharing := userlib.SymEnc(
		sharingEncKey,
		userlib.RandomBytes(16),
		updatedSharingBytes,
	)

	sharingMac, err := userlib.HMACEval(
		sharingMacKey,
		encryptedSharing,
	)
	if err != nil {
		return uuid.Nil, err
	}

	storedSharing.EncryptedData = encryptedSharing
	storedSharing.Mac = sharingMac

	updatedStoredSharingBytes, err := json.Marshal(storedSharing)
	if err != nil {
		return uuid.Nil, err
	}

	userlib.DatastoreSet(sharingUUID, updatedStoredSharingBytes)
	}

	userlib.DatastoreSet(
		recipientReferenceUUID,
		storedRecipientRefBytes,
	)

	userlib.DatastoreSet(
		invitationPtr,
		storedInvitationBytes,
	)

	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	senderVerifyKey, exists := userlib.KeystoreGet(senderUsername + "_verify")
	if !exists {
		return errors.New("sender does not exist")
	}

	filenameKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("filename:" + filename),
	)
	if err != nil {
		return err
	}

	fileUUID, err := uuid.FromBytes(filenameKeyBytes[:16])
	if err != nil {
		return err
	}

	_, exists = userlib.DatastoreGet(fileUUID)
	if exists {
		return errors.New("filename already exists")
	}

	storedInvitationBytes, exists := userlib.DatastoreGet(invitationPtr)
	if !exists {
		return errors.New("invitation does not exist")
	}

	var storedInvitation StoredInvitation
	err = json.Unmarshal(storedInvitationBytes, &storedInvitation)
	if err != nil {
		return err
	}

	signedBytes := append(
		[]byte{},
		storedInvitation.EncryptedKey...,
	)
	signedBytes = append(signedBytes, storedInvitation.EncryptedData...)
	signedBytes = append(signedBytes, storedInvitation.Mac...)

	err = userlib.DSVerify(
		senderVerifyKey,
		signedBytes,
		storedInvitation.Signature,
	)
	if err != nil {
		return errors.New("invalid invitation signature")
	}

	invitationKey, err := userlib.PKEDec(
		userdata.PrivateDecKey,
		storedInvitation.EncryptedKey,
	)
	if err != nil {
		return err
	}

	invitationEncKeyBytes, err := userlib.HashKDF(
		invitationKey,
		[]byte("invitation encryption"),
	)
	if err != nil {
		return err
	}

	invitationMacKeyBytes, err := userlib.HashKDF(
		invitationKey,
		[]byte("invitation authentication"),
	)
	if err != nil {
		return err
	}

	expectedMac, err := userlib.HMACEval(
		invitationMacKeyBytes[:16],
		storedInvitation.EncryptedData,
	)
	if err != nil {
		return err
	}

	if !userlib.HMACEqual(expectedMac, storedInvitation.Mac) {
		return errors.New("invitation was modified")
	}

	if len(storedInvitation.EncryptedData) < 16 {
		return errors.New("invalid invitation")
	}

	invitationBytes := userlib.SymDec(
		invitationEncKeyBytes[:16],
		storedInvitation.EncryptedData,
	)

	var invitation Invitation
	err = json.Unmarshal(invitationBytes, &invitation)
	if err != nil {
		return err
	}

	if invitation.Sender != senderUsername {
		return errors.New("incorrect sender")
	}

	if invitation.Recipient != userdata.Username {
		return errors.New("incorrect recipient")
	}

	if invitation.ReferenceUUID == uuid.Nil {
		return errors.New("invalid reference UUID")
	}

	if len(invitation.ReferenceKey) != 16 {
		return errors.New("invalid reference key")
	}

	_, exists = userlib.DatastoreGet(invitation.ReferenceUUID)
	if !exists {
		return errors.New("file reference does not exist")
	}

	var namespaceEntry NamespaceEntry
	namespaceEntry.ReferenceUUID = invitation.ReferenceUUID
	namespaceEntry.ReferenceKey = invitation.ReferenceKey

	namespaceBytes, err := json.Marshal(namespaceEntry)
	if err != nil {
		return err
	}

	namespaceEncKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("namespace encryption:" + filename),
	)
	if err != nil {
		return err
	}

	namespaceMacKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("namespace authentication:" + filename),
	)
	if err != nil {
		return err
	}

	encryptedNamespace := userlib.SymEnc(
		namespaceEncKeyBytes[:16],
		userlib.RandomBytes(16),
		namespaceBytes,
	)

	namespaceMac, err := userlib.HMACEval(
		namespaceMacKeyBytes[:16],
		encryptedNamespace,
	)
	if err != nil {
		return err
	}

	var storedNamespace StoredFile
	storedNamespace.EncryptedData = encryptedNamespace
	storedNamespace.Mac = namespaceMac

	storedNamespaceBytes, err := json.Marshal(storedNamespace)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(fileUUID, storedNamespaceBytes)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	sharingUUIDBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("sharing uuid:" + filename),
	)
	if err != nil {
		return err
	}

	sharingUUID, err := uuid.FromBytes(sharingUUIDBytes[:16])
	if err != nil {
		return err
	}

	sharingKeyBytes, err := userlib.HashKDF(
		userdata.NamespaceKey,
		[]byte("sharing key:" + filename),
	)
	if err != nil {
		return err
	}

	sharingEncKey, sharingMacKey, err := getSharingKeys(sharingKeyBytes[:16])
	if err != nil {
		return err
	}

	storedSharingBytes, exists := userlib.DatastoreGet(sharingUUID)
	if !exists {
		return errors.New("sharing registry does not exist")
	}

	var storedSharing StoredSharingRecord
	err = json.Unmarshal(storedSharingBytes, &storedSharing)
	if err != nil {
		return err
	}

	expectedMac, err := userlib.HMACEval(
		sharingMacKey,
		storedSharing.EncryptedData,
	)
	if err != nil {
		return err
	}

	if !userlib.HMACEqual(expectedMac, storedSharing.Mac) {
		return errors.New("sharing registry modified")
	}

	if len(storedSharing.EncryptedData) < 16 {
		return errors.New("invalid sharing registry")
	}

	sharingBytes := userlib.SymDec(
		sharingEncKey,
		storedSharing.EncryptedData,
	)

	var sharingRecord SharingRecord
	err = json.Unmarshal(sharingBytes, &sharingRecord)
	if err != nil {
		return err
	}

	found := false
	remainingUsers := make([]ShareInfo, 0)

	for _, share := range sharingRecord.Users {
		if share.Username == recipientUsername {
			userlib.DatastoreDelete(share.ReferenceUUID)
			found = true
		} else {
			remainingUsers = append(remainingUsers, share)
		}
	}

	if !found {
		return errors.New("recipient was not shared with")
	}

	sharingRecord.Users = remainingUsers

	updatedBytes, err := json.Marshal(sharingRecord)
	if err != nil {
		return err
	}

	encryptedSharing := userlib.SymEnc(
		sharingEncKey,
		userlib.RandomBytes(16),
		updatedBytes,
	)

	newMac, err := userlib.HMACEval(
		sharingMacKey,
		encryptedSharing,
	)
	if err != nil {
		return err
	}

	storedSharing.EncryptedData = encryptedSharing
	storedSharing.Mac = newMac

	finalBytes, err := json.Marshal(storedSharing)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(sharingUUID, finalBytes)

	return nil
}

func getSharingKeys(sharingKey []byte) ([]byte, []byte, error) {
	encKeyBytes, err := userlib.HashKDF(
		sharingKey,
		[]byte("sharing encryption"),
	)
	if err != nil {
		return nil, nil, err
	}

	macKeyBytes, err := userlib.HashKDF(
		sharingKey,
		[]byte("sharing authentication"),
	)
	if err != nil {
		return nil, nil, err
	}

	return encKeyBytes[:16], macKeyBytes[:16], nil
}
