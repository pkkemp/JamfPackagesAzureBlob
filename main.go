package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/Azure/azure-storage-blob-go/azblob"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const cdnEndpoint ="dist-usaf.azureedge.us"
const blobEndpoint = "jamfpackages.blob.core.usgovcloudapi.net"
const accountKey = "Sb1DifmMa/g+e7mRtJiSHMWaKa+TOYZaGOmZ2nrpLwThPFmC7o/uODPY+NHJ2Z3rm5OZ5JHZjbFOrabTtn3f4A=="
const accountName = "jamfpackages"

var (
	username = "abc"
	password = "123"

)


func main() {




	handler := http.HandlerFunc(handleRequest)
	http.Handle("/Packages/", handler)
	http.ListenAndServe(":8080", nil)
}

func init() {
	sasSigner = NewSigner("key1", "Sb1DifmMa/g+e7mRtJiSHMWaKa+TOYZaGOmZ2nrpLwThPFmC7o/uODPY+NHJ2Z3rm5OZ5JHZjbFOrabTtn3f4A==")
}

func handleRequest(w http.ResponseWriter, r *http.Request) {

	//u, p, ok := r.BasicAuth()
	//if !ok {
	//	fmt.Println("Error parsing basic auth")
	//	w.WriteHeader(401)
	//	return
	//}
	//if u != username {
	//	fmt.Printf("Username provided is correct: %s\n", u)
	//	w.WriteHeader(401)
	//	return
	//}
	//if p != password {
	//	fmt.Printf("Password provided is correct: %s\n", u)
	//	w.WriteHeader(401)
	//	return
	//}
	//fmt.Printf("Username: %s\n", u)
	//fmt.Printf("Password: %s\n", p)
	path := r.URL.Path
	splitPath := strings.SplitN(path, "/", 3)
	//newPath := "/" + strings.ToLower(splitPath[1]) + "/" + splitPath[2]



	//cdnURL := "https://" + blobEndpoint + newPath
	//sas, _ := sasSigner.SignWithDuration(cdnURL, time.Minute * 20, newPath)
	//signedURL := cdnURL + "?"+ sas
	credential, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	if err != nil {
		log.Fatal(err)
	}



	// This is the name of the container and blob that we're creating a SAS to.
	containerName := "packages" // Container names require lowercase
	blobName := splitPath[2]   // Blob names can be mixed case

	// Set the desired SAS signature values and sign them with the shared key credentials to get the SAS query parameters.
	sasQueryParams, err := azblob.BlobSASSignatureValues{
		Protocol:      azblob.SASProtocolHTTPS,                     // Users MUST use HTTPS (not HTTP)
		ExpiryTime:    time.Now().UTC().Add(48 * time.Hour), // 48-hours before expiration
		ContainerName: containerName,
		BlobName:      blobName,

		// To produce a container SAS (as opposed to a blob SAS), assign to Permissions using
		// ContainerSASPermissions and make sure the BlobName field is "" (the default).
		Permissions: azblob.BlobSASPermissions{Add: false, Read: true, Write: false}.String(),
	}.NewSASQueryParameters(credential)
	if err != nil {
		log.Fatal(err)
	}

	// Create the URL of the resource you wish to access and append the SAS query parameters.
	// Since this is a blob SAS, the URL is to the Azure storage blob.
	qp := sasQueryParams.Encode()
	urlToSendToSomeone := fmt.Sprintf("https://%s.blob.core.usgovcloudapi.net/%s/%s?%s",
		accountName, containerName, blobName, qp)

	http.Redirect(w, r, urlToSendToSomeone, 302)
	return
}

func generateSasToken(resourceUri string, signingKey string, expiration string) {


}

// Signer provides SAS token generation for use in Service Bus and Event Hub
type Signer struct {
	KeyName string
	Key     string
}

// NewSigner builds a new SAS signer for use in generation Service Bus and Event Hub SAS tokens
func NewSigner(keyName, key string) *Signer {
	return &Signer{
		KeyName: keyName,
		Key:     key,
	}
}

// SignWithDuration signs a given for a period of time from now
func (s *Signer) SignWithDuration(uri string, interval time.Duration, resource string) (signature, expiry string) {
	expiry = signatureExpiry(time.Now().UTC(), interval)
	return s.SignWithExpiry(uri, resource), expiry
}

// SignWithExpiry signs a given uri with a given expiry string
func (s *Signer) SignWithExpiry(uri, resource string) string {



	audience := strings.ToLower(url.QueryEscape(uri))


	StorageServicesVersion := "2020-02-10"
	//SRT tells what kind of storage object we'll be accessing, in this case an object, so "o"
	srt := "o"
	//SP tells what kind of operations may be performed against this resource, we only want read and execute
	Permissions := "rx"
	//ST is when the access signature becomes valid
	loc, _ := time.LoadLocation("UTC")
	sTime := time.Now().In(loc)
	//subtract 15 minutes from current time to account for clock skew
	sTime = sTime.Add(-time.Minute*15)
	StartTime := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ",
		sTime.Year(), sTime.Month(), sTime.Day(),
		sTime.Hour(), sTime.Minute(), sTime.Second())

	//SE is the expiration time for the signature

	eTime := time.Now().In(loc)

	eTime.Zone()
	//add 20 minutes from now
	eTime = eTime.Add(time.Minute*20)
	ExpirationTime := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ",
		eTime.Year(), eTime.Month(), eTime.Day(),
		eTime.Hour(), eTime.Minute(), eTime.Second())


	ResourceType:= "b"
	Protocol := "https"

	sts := stringToSign(audience, Permissions, StartTime, ExpirationTime, Protocol, resource, StorageServicesVersion)
	Signature := s.signString(sts)



	return fmt.Sprintf("sv=%s&ss=%s&srt=%s&st=%s&se=%s&sp=%s&spr=%s&sig=%s", StorageServicesVersion, ResourceType, srt,  StartTime, ExpirationTime, Permissions, Protocol, Signature)
	//return fmt.Sprintf("SharedAccessSignature sv=%s&sig=%s&se=%s&skn=%s", audience, sig, expiry, s.KeyName)
}

func signatureExpiry(from time.Time, interval time.Duration) string {
	t := from.Add(interval).Round(time.Second).Unix()
	return strconv.FormatInt(t, 10)
}

func stringToSign(uri, permissions string, start string, expiry string, protocol string, resource string, version string) string {
	sts := uri + "\n" + start + "\n" + expiry + "\n" + resource + "\n" + permissions + "\n" + "\n" + version + "\n" + "\n" + "file; attachment + \n" + "\n" + "\n" + "binary"
	return sts
}

func (s *Signer) signString(str string) string {
	h := hmac.New(sha256.New, []byte(s.Key))
	h.Write([]byte(str))
	encodedSig := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return url.QueryEscape(encodedSig)
}