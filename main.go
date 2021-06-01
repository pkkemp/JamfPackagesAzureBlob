package main

import (
	"fmt"
	"github.com/Azure/azure-storage-blob-go/azblob"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const cdnEndpoint ="dist-usaf.azureedge.us"
const blobEndpoint = "jamfpackages.blob.core.usgovcloudapi.net"
const accountKey = "Sb1DifmMa/g+e7mRtJiSHMWaKa+TOYZaGOmZ2nrpLwThPFmC7o/uODPY+NHJ2Z3rm5OZ5JHZjbFOrabTtn3f4A=="
const accountName = "jamfpackages"

var (
	username = os.Getenv("BASIC_AUTH_USERNAME")
	password = os.Getenv("BASIC_AUTH_PASSWORD")
	accountKey = os.Getenv("ACCOUNT_KEY")
    accountName = os.Getenv("ACCOUNT_NAME")
    blobEndpoint = os.Getenv("BLOB_ENDPOINT")
    cdnEndpoint = os.Getenv("CDN_ENDPOINT")
)


func main() {

	handler := http.HandlerFunc(handleRequest)
	http.Handle("/Packages/", handler)
	http.ListenAndServe(":8080", nil)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {

	u, p, ok := r.BasicAuth()
	if !ok {
		fmt.Println("Error parsing basic auth")
		w.WriteHeader(401)
		return
	}
	if u != username {
		fmt.Printf("Username provided is correct: %s\n", u)
		w.WriteHeader(401)
		return
	}
	if p != password {
		fmt.Printf("Password provided is correct: %s\n", u)
		w.WriteHeader(401)
		return
	}
	//fmt.Printf("Username: %s\n", u)
	//fmt.Printf("Password: %s\n", p)
	path := r.URL.Path
	splitPath := strings.SplitN(path, "/", 3)
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
	urlToSendToSomeone := fmt.Sprintf("https://%s/%s/%s?%s",
		cdnEndpoint, containerName, blobName, qp)

	http.Redirect(w, r, urlToSendToSomeone, 302)
	return
}
