package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
    "net"
	"strings"

	// SPIFFE
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	// dasvid lib
	dasvid "github.com/marco-developer/dasvid/poclib"
)

const (
    socketPath    = "unix:///tmp/spire-agent/public/api.sock"
)

type PocData struct {
    AccessToken     			string `json:",omitempty"`
    PublicKey					string `json:",omitempty"`
    OauthSigValidation 			*bool `json:",omitempty"`
    OauthExpValidation 			*bool `json:",omitempty"`
    OauthExpRemainingTime		string `json:",omitempty"`
    OauthClaims					map[string]interface{} `json:",omitempty"`
    DASVIDToken					string `json:",omitempty"`
    DASVIDClaims 				map[string]interface{} `json:",omitempty"`
    DasvidExpValidation 		*bool `json:",omitempty"`
    DasvidExpRemainingTime		string `json:",omitempty"`
    DasvidSigValidation 		*bool `json:",omitempty"`
 }


type Balance struct {
    Balance     string `json:",omitempty"`
}

func main(){

    // creates empty context to recieve an incoming request
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
    if err != nil {
        log.Fatalf("Unable to create X509 source: %v", err)
    }
    defer source.Close()
}


func GetOutboundIP() net.IP {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)

    return localAddr.IP
}

func validate_dasvid(data string) bool {

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    //getting assertingwl ip
    Iplocal := GetOutboundIP()
    StrIPlocal := fmt.Sprintf("%v", Iplocal)
    serverURL := StrIPlocal + ":8443"


    url_parts := []string{"https://", serverURL, "/validate?DASVID=", data}

    endpoint := strings.Join(url_parts, "")


    // Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket path
    source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
    if err != nil {
        log.Fatalf("Unable to create X509Source %v", err)
    }
    defer source.Close()

    // Allowed SPIFFE ID
    serverID := spiffeid.RequireTrustDomainFromString("example.org")

    // Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match allowed SPIFFE ID rule
    tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeMemberOf(serverID))
    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    }


    //sending request
    r, err := client.Get(endpoint)
    if err != nil {
        log.Fatalf("Error connecting to %q: %v", serverURL, err)
    }

    defer r.Body.Close()
    body, err := ioutil.ReadAll(r.Body)
    if err != nil {
        log.Fatalf("Unable to read body: %v", err)
    }

    var result PocData
    json.Unmarshal(body, &result)

    if (*result.DasvidExpValidation) && (*result.DasvidSigValidation) {
        return true
    }

    return false

}


func get_data(w http.ResponseWriter, r *http.Request){

    data := r.FormValue("DASVID")
    if !(validate_dasvid(data)) {

        log.Printf("Invalid DA-SVID")
        json.NewEncoder(w).Encode(nil)
        return
    }


    //in this example we will consider that only "web" subjects will be able request data
    dasvid_claims := dasvid.ParseTokenClaims(data)
    if dasvid_claims["sub"].(string) != "web"{

        log.Printf("Unauthorized subject workload!")
        json.NewEncoder(w).Encode(nil)
        return
    }

    //TODO:make data request

    responde
    json.NewEncoder(w).Encode()


    //TODO:write data on response writer


}
