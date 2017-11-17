package proj2


// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"
	
	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// For the useful little debug printing function
	"fmt"
	"time"
	"os"
	"strings"

	// I/O
	"io"
	
	// Want to import errors
	"errors"
	
	// These are imported for the structure definitions.  You MUST
	// not actually call the functions however!!!
	// You should ONLY call the cryptographic functions in the
	// userlib, as for testing we may add monitoring functions.
	// IF you call functions in here directly, YOU WILL LOSE POINTS
	// EVEN IF YOUR CODE IS CORRECT!!!!!
	"crypto/rsa"
)


// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	debugMsg("UUID as string:%v", f.String())
	
	// Example of writing over a byte of f
	f[0] = 10
	debugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	debugMsg("The hex: %v", h)
	
	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d,_ := json.Marshal(f)
	debugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	debugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	debugMsg("Creation of error %v", errors.New("This is an error"))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *rsa.PrivateKey
	key,_ = userlib.GenerateRSAKey()
	debugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range(ret){
		ret[x] = data[x]
	}
	return 
}

// Helper function: Returns a byte slice of the specificed
// size filled with random data
func randomBytes(bytes int) (data []byte) {
	data = make([]byte, bytes)
	if _, err := io.ReadFull(userlib.Reader, data); err != nil {
		panic(err)
	}
	return 
}

var DebugPrint = false

// Helper function: Does formatted printing to stderr if
// the DebugPrint global is set.  All our testing ignores stderr,
// so feel free to use this for any sort of testing you want
func debugMsg(format string, args ...interface{}) {
	if DebugPrint{
		msg := fmt.Sprintf("%v ", time.Now().Format("15:04:05.00000"))
		fmt.Fprintf(os.Stderr,
			msg + strings.Trim(format, "\r\n ") + "\n", args...)
	}
}

func CFBEncrypt(key []byte, data []byte) (encryptedBytes []byte){
	encryptedBytes = make([]byte, userlib.BlockSize + len(data))
	iv := encryptedBytes[:userlib.BlockSize]
	// Load random data
	if _, err := io.ReadFull(userlib.Reader, iv); err != nil {
		panic(err)
	}
    cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(encryptedBytes[userlib.BlockSize:], data) /* encryptedBytes. */
	return encryptedBytes
}

func CFBDecrypt(key []byte, encryptedData []byte) (decryptedBytes []byte) {
	/* Decrypt userDataBytes. */
	cipher := userlib.CFBDecrypter(key, encryptedData[:userlib.BlockSize]) /* IV is located at the first block of ciphertext. */
	cipher.XORKeyStream(encryptedData[userlib.BlockSize:], encryptedData[userlib.BlockSize:])
	decryptedBytes = encryptedData[userlib.BlockSize:]
	return decryptedBytes
}

func HMACData(key []byte, data []byte) (HMACBytes []byte) {
	hmac := userlib.NewHMAC(key)
	hmac.Reset()
	hmac.Write(data)
	HMACBytes = hmac.Sum(nil)
	return HMACBytes
}

func bytesToString(bytes []byte) (stringBytes string) {
	uuid, err  := uuid.ParseBytes(bytes)
	if (err != nil) {
		return "Error hex.EncodeToString."
	}
	stringBytes = uuid.String()
	return stringBytes
}

type FileMetaData struct {
	Locations []string
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	MKey []byte // Mac Key.
	EKey []byte // Encryption Key. 
	RSAKey *rsa.PrivateKey
	FileLocations map[string]string
	FileKeys map[string][]byte

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// This creates a user. It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error){
	var userdata User
	userdata.Username = username
	userdata.Password = password
	userdata.FileLocations = make(map[string]string)
	userdata.FileKeys = make(map[string][]byte)

	/* Generate macKey. */
	keys := userlib.PBKDF2Key([]byte(password), []byte(username), 144)
	mKey := keys[:128]
	userdata.MKey = mKey
	eKey := keys[128:]
	userdata.EKey = eKey

	/* Generate RSA public key. */
	RSAKey, err := userlib.GenerateRSAKey()
	pubKey := RSAKey.PublicKey
	userlib.KeystoreSet(username, pubKey)
	userdata.RSAKey = RSAKey

	/* Generate HMAC and create hashed username and password variable. */
	userKeyBytes := HMACData(mKey, []byte(username + password))

	userDataBytes,_ := json.Marshal(userdata) /* Put userdata into bytes. */

	encryptedBytes := CFBEncrypt(eKey, userDataBytes)
	HMACEncryptedBytes := HMACData(mKey, encryptedBytes)
	encryptedBytes = append(encryptedBytes, HMACEncryptedBytes[:]...)

	userKey := hex.EncodeToString(userKeyBytes)
	userlib.DatastoreSet(userKey, encryptedBytes) /* Store encryptedBytes associated with username. */
	return &userdata, err
}

/* User defined. */
func hash(s string) []byte {
	toHash := []byte(s)
	hasher := userlib.NewSHA256()
	hasher.Write(toHash)
	hash := hasher.Sum(nil)
	return hash
}

// This fetches the user information from the Datastore. It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	keys := userlib.PBKDF2Key([]byte(password), []byte(username), 144)
	mKey := keys[:128] // MacKey.
	eKey := keys[128:] // EncKey. 
	userKeyBytes := HMACData(mKey, []byte(username + password))
	userKey := hex.EncodeToString(userKeyBytes)

	userDataBytes, ok := userlib.DatastoreGet(userKey) /* Get encrypted concatenated by HMAC. */
	if (!ok) {
		return nil, errors.New("Error getting userDataBytes.")
	}
	dataLength := len(userDataBytes)
	macLength := userlib.HashSize /* HashSize = MacSize. */ 

	/* Verify HMAC and decrypt data if HMAC is valid. */
	HMACEncryptedBytes := userDataBytes[(dataLength - macLength):]
	encryptedBytes := userDataBytes[:(dataLength - macLength)]

	checkHMAC := HMACData(mKey, encryptedBytes)
	if (!userlib.Equal(checkHMAC, HMACEncryptedBytes)) {
		return nil, errors.New("HMAC doesn't match data.")
	}

	/* Decrypt userDataBytes. */
	userDataBytes = CFBDecrypt(eKey, encryptedBytes)	

	/* userDataBytes now decrypted. Proceed to unmarshal decrypted data into userdataptr before returning pointer. */
	err = json.Unmarshal(userDataBytes, &userdataptr)
	if (err != nil) {
		return nil, err
	} else {
		return userdataptr, err
	}
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!

/* Use privateKey to store each individual file to make revocation easier. New for each metadata as well. */
func (userdata *User) StoreFile(filename string, data []byte) {	
	/* Generate encryption key and MACKey for this particular file. */
	keys := userlib.PBKDF2Key([]byte(filename), []byte(userdata.Password), 144) 
	fileMacKey := keys[:128] 
	fileEncKey := keys[128:]

	/* Encrypt data to store in a random location. */
	encryptedData := CFBEncrypt(fileEncKey, data)
	HMACencryptedData := HMACData(fileMacKey, encryptedData)
	encryptedData = append(encryptedData, HMACencryptedData[:]...)
	
	encDataLocationBytes := randomBytes(128)
	encDataLocation := hex.EncodeToString(encDataLocationBytes)
	userlib.DatastoreSet(encDataLocation, encryptedData)

	/* Create metadata that points to random location storing the data. */
	var metadata FileMetaData
	metadata.Locations = append(metadata.Locations, encDataLocation)
	locationMetaDataBytes := randomBytes(128)
	locationMetaData := hex.EncodeToString(locationMetaDataBytes)
	fileMetaLoc := locationMetaData

	/* Encrypt metadata. HMAC before storing into DataStore. */
	metadataBytes, err := json.Marshal(metadata)

	if (err != nil) {
		return
	}
	encryptedMeta := CFBEncrypt(fileEncKey, metadataBytes)
	HMACencryptedMeta := HMACData(fileMacKey, encryptedMeta)
	encryptedMeta = append(encryptedMeta, HMACencryptedMeta[:]...)
	userlib.DatastoreSet(fileMetaLoc, encryptedMeta) // Store metadata in random location. 

	/* Update file dictionaries containing relevant locations and keys. */
	userdata.FileLocations[filename] = fileMetaLoc
	userdata.FileKeys[filename] = keys

	/* Reencrypt userdata and restore into DataStore. */
	userDataBytes, _ := json.Marshal(userdata) /* Put userdata into bytes. */
	encryptedBytes  := CFBEncrypt(userdata.EKey, userDataBytes)
	HMACEncryptedBytes := HMACData(userdata.MKey, encryptedBytes)
	encryptedBytes = append(encryptedBytes, HMACEncryptedBytes[:]...)

	userKeyBytes := HMACData(userdata.MKey, []byte(userdata.Username + userdata.Password))
	userKey := hex.EncodeToString(userKeyBytes)

	userlib.DatastoreSet(userKey, encryptedBytes) /* Store reencrypted data associated with userKey. */
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	fileMetaLoc := userdata.FileLocations[filename]
	fileKeys := userdata.FileKeys[filename]
	fileMacKey := fileKeys[:128]
	fileEncKey := fileKeys[128:]

	/* Get metadata and check authentication. */
	bytes, ok := userlib.DatastoreGet(fileMetaLoc)
	if (!ok) {
		return errors.New("DatastoreGet failed.")
	}

	dataLength := len(bytes)
	macLength := userlib.HashSize
	HMACmetaDataBytes := bytes[(dataLength - macLength):]
	ENCmetaDataBytes := bytes[:(dataLength - macLength)]

	checkHMAC := HMACData(fileMacKey, ENCmetaDataBytes)

	if (!userlib.Equal(checkHMAC, HMACmetaDataBytes)) {
		return errors.New("HMAC doesn't match metadata.")
	}

	/* Decrypt the encrypted metadata. */
	metaDataBytes := CFBDecrypt(fileEncKey, ENCmetaDataBytes)

	/* Proceed to unmarshal metadata. */
	var metadata FileMetaData 
	err = json.Unmarshal(metaDataBytes, &metadata)
	if (err != nil) {
		return err
	}

	/* Encrypt the data passed into the function. */
	encryptedData := CFBEncrypt(fileEncKey, data)
	HMACencryptedData := HMACData(fileMacKey, encryptedData)
	encryptedData = append(encryptedData, HMACencryptedData[:]...)

	/* Store this encryptedData at a random location. */
	randomLocationBytes := randomBytes(128)
	randomLocation := hex.EncodeToString(randomLocationBytes)
	metadata.Locations = append(metadata.Locations, randomLocation)
	userlib.DatastoreSet(randomLocation, encryptedData) // Store encryptedData at random location.

	/* Marshal updated metadata, encrypt it, HMAC it, and restore into userlib.DatastoreSet. */
	metaDataBytes, _ = json.Marshal(metadata) /* Put userdata into bytes. */
	encryptedMeta := CFBEncrypt(fileEncKey, metaDataBytes)
	HMACencryptedMeta := HMACData(fileMacKey, encryptedMeta)
	encryptedMeta = append(encryptedMeta, HMACencryptedMeta[:]...)

	userlib.DatastoreSet(fileMetaLoc, encryptedMeta) /* Store encrypted updated metadata into hashedFileName again. */
	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string)(data []byte, err error) {
	/* Get the file. Authenticate the file by comparing with HMAC. Decrypt the file. Get metadata.
	   Iterate through the metadata and decrypt each block. Concatenate all of the blocks before
	   finally returning the decrypted and concatenated data. */

	fileMetaLoc := userdata.FileLocations[filename]
	fileKeys := userdata.FileKeys[filename]
	fileMacKey := fileKeys[:128]
	fileEncKey := fileKeys[128:]

	/* Get metadata and check authentication. */
	bytes, ok := userlib.DatastoreGet(fileMetaLoc)

	copyBytes := make([]byte, len(bytes))
	copy(copyBytes, bytes)
	userlib.DatastoreSet(fileMetaLoc, copyBytes)

	if (!ok) {
		return nil, errors.New("DatastoreGet failed.")
	}

	dataLength := len(bytes)
	macLength := userlib.HashSize
	HMACmetaDataBytes := bytes[(dataLength - macLength):]
	ENCmetaDataBytes := bytes[:(dataLength - macLength)]

	checkHMAC := HMACData(fileMacKey, ENCmetaDataBytes)

	if (!userlib.Equal(checkHMAC, HMACmetaDataBytes)) {
		return nil, errors.New("HMAC doesn't match metadata.")
	}

	/* Decrypt the encrypted metadata. */
	metaDataBytes := CFBDecrypt(fileEncKey, ENCmetaDataBytes)

	/* Proceed to unmarshal metadata. */
	var metadata FileMetaData 
	err = json.Unmarshal(metaDataBytes, &metadata)
	if (err != nil) {
		return nil, err
	}

	/* Decrypt data located at each randomlocation, and append all of the decrypted data. Return the data. */
	length := len(metadata.Locations)
	var fullFile []byte
	for i := 0; i < length; i++ {
		location := metadata.Locations[i]
		block, ok :=  userlib.DatastoreGet(location) /* Block of data at particular location. */
		
		copyBlock := make([]byte, len(block))
		copy(copyBlock, block)
		userlib.DatastoreSet(location, copyBlock)

		if (!ok) {
			return nil, errors.New("Error getting block.")
		}

		blockLength := len(block)
		macLength := userlib.HashSize

		HMACencryptedBlock := block[(blockLength - macLength):]
		encryptedBlock := block[:(blockLength - macLength)]

		checkHMAC := HMACData(fileMacKey, encryptedBlock)

		if (!userlib.Equal(checkHMAC, HMACencryptedBlock)) {
			return nil, errors.New("HMAC of block doesn't match encrypted block.")
		}

		decryptedBlock := CFBDecrypt(fileEncKey, encryptedBlock)

		fullFile = append(fullFile, decryptedBlock[:]...) /* At end of loop, all blocks decrypted. */
	}
	return fullFile, nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialize/deserialize in the data store.

type sharingRecord struct {
	FileLoc string
	FileKeys []byte
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string)(
	msgid string, err error){

	/* Retrieve file location and relevant keys. */
	fileMetaLoc := userdata.FileLocations[filename]
	fileKeys := userdata.FileKeys[filename]

	/* Create sharing record. */
	var share sharingRecord
	share.FileLoc = fileMetaLoc
	share.FileKeys = fileKeys

	shareDataBytes, _ := json.Marshal(share) 
	fmt.Printf("\n\n" + string(shareDataBytes))

	recipientPubKey, _ := userlib.KeystoreGet(recipient)

	/* Sign with user's private key. */
	sign, err := userlib.RSASign(userdata.RSAKey, shareDataBytes) 
	if (err != nil) {
		return "RSASign didn't work.", err
	}

	/* Encrypt with recipient's public key. */
	encryptedShare, err := userlib.RSAEncrypt(&recipientPubKey, shareDataBytes, []byte(""))
	if (err != nil) {
		return "RSAEncrypt didn't work.", err
	}

	msgidBytes := append(sign, encryptedShare[:]...)
	msgid = string(msgidBytes[:])
	return msgid, nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {

	msgidBytes := []byte(msgid)

	sign := msgidBytes[:256]
	encryptedShare := msgidBytes[256:]

	/* Decrypted share should be equivalent to the marshaled sharing record struct. */
	decryptedShare, err := userlib.RSADecrypt(userdata.RSAKey, encryptedShare, []byte(""))
	if (err != nil) {
		errors.New("Decryption fail.")
	}

	senderPubKey, _ := userlib.KeystoreGet(sender)

	/* If not error, verification is successful and sender has indeed sent the message. */
	err = userlib.RSAVerify(&senderPubKey, decryptedShare, sign)
	if (err != nil) {
		errors.New("RSA verification failure.")
	}

	/* Since verification is successful, we can proceed to use decryptedShare to update
	   userdata information concerning fileLoc and fileKeys. */

	/* Unmarshal decryptedShare so that share holds relevant data. */
	var share sharingRecord
	err = json.Unmarshal(decryptedShare, &share)
	if (err != nil) {
		return err
	}

	/* Update fileLocations and fileKeys maps in userdata. Afterwards, reencrypt the 
	   userdata before restoring information into the userlib.DatastoreSet. */
	userdata.FileLocations[filename] = share.FileLoc
	userdata.FileKeys[filename] = share.FileKeys

	userDataBytes, _ := json.Marshal(userdata) /* Put userdata into bytes. */
	encryptedBytes := CFBEncrypt(userdata.EKey, userDataBytes)
	HMACencryptedBytes := HMACData(userdata.MKey, encryptedBytes)
	encryptedBytes = append(encryptedBytes, HMACencryptedBytes[:]...)

	userKeyBytes := HMACData(userdata.MKey, []byte(userdata.Username + userdata.Password))
	userKey := hex.EncodeToString(userKeyBytes)
	userlib.DatastoreSet(userKey, encryptedBytes) /* Store encryptedBytes associated with username. */

	/* User should now have access to the fileLocation and the fileKeys. This will allow the user
	   to load, append, and modify files. */

	return nil
}

// Removes access for all others.  

/* Revocation entails moving the location of the metadata, and the contents of the metadata
   (location of the blocks, encryption key, hmac key) so that other users can no longer 
   have access. Need to ensure that RevokeFile is being called by the owner of the user.
   After this is done, just change the keys of each file as well as the location of the metadata.
   But the location of the metadata is currently HMAC(password, fileName), so what should I change
   it to now? Changing it to something else is probably fine. */

func (userdata *User) RevokeFile(filename string) (err error){
	/* Delete fileData from the datastore. Delete metadata from the datastore. */
	fileMetaLoc := userdata.FileLocations[filename]
	fileKeys := userdata.FileKeys[filename]
	fileEncKey := fileKeys[:128]
	fileMacKey := fileKeys[128:]

	/* Get all of the filedata. Store the filedata at a different randomized location. 
	   Get the metadata. Store the metadata at a different randomized location. */

	/* Get metadata. Need to store this somewhere else now. */
	bytes, ok := userlib.DatastoreGet(fileMetaLoc)
	if (!ok) {
		return errors.New("Error getting metadata.")
	}
	dataLength := len(bytes)
	macLength := userlib.HashSize
	HMACmetaDataBytes := bytes[(dataLength - macLength):]
	ENCmetaDataBytes := bytes[:(dataLength - macLength)]

	checkHMAC := HMACData(fileMacKey, ENCmetaDataBytes)
	if (!userlib.Equal(checkHMAC, HMACmetaDataBytes)) {
		return errors.New("HMAC doesn't match metadata.")
	}
	/* After above HMAC check, we can be assured that the metadata is correct. */

	/* Decrypt metadata and reencrypt with new keys. */
	metadata := CFBDecrypt(fileEncKey, ENCmetaDataBytes)
	newKeys := randomBytes(256)
	newEncKey := newKeys[:128] // newKeys may not necessarily be of length 256. (ERROR)
	newMacKey := newKeys[128:]

	/* Encrypt and HMAC metadata with new keys. */
	encMetaData := CFBEncrypt(newEncKey, metadata)
	HMACmetadata := HMACData(newMacKey, encMetaData)
	encMetaData = append(encMetaData, HMACmetadata[:]...)

	/* Create new random location for metadata. */
	metaNewLocationBytes := randomBytes(128)
	metaNewLocation := hex.EncodeToString(metaNewLocationBytes)

	/* Delete original location of metadata. */
	userlib.DatastoreDelete(fileMetaLoc)

	/* Relocate metaDataBytes. */
	userlib.DatastoreSet(metaNewLocation, encMetaData)

	/* Update maps located inside user struct. */
	userdata.FileLocations[filename] = metaNewLocation
	userdata.FileKeys[filename] = newKeys

	/* Reencrypt userdata before storing again. */
	userKeyBytes := HMACData(userdata.MKey, []byte(userdata.Username + userdata.Password))

	userDataBytes, _ := json.Marshal(userdata) /* Put userdata into bytes. */
	encryptedBytes := CFBEncrypt(userdata.EKey, userDataBytes)
	HMACEncryptedBytes := HMACData(userdata.MKey, encryptedBytes)
	encryptedBytes = append(encryptedBytes, HMACEncryptedBytes[:]...)

	userKey := hex.EncodeToString(userKeyBytes)
	userlib.DatastoreSet(userKey, encryptedBytes) /* Store encryptedBytes associated with username. */

	return nil
}