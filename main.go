package main

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "io/ioutil"
    "log"
    "net"
    "net/http"
    "strings"

    //Database
    "database/sql"

    // SPIFFE
    "github.com/spiffe/go-spiffe/v2/spiffeid"
    "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
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
    Account_id  string `json:",omitempty"`
    Balance     string `json:",omitempty"`
}

func main(){



    // creates empty context to recieve an incoming request
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    http.HandleFunc("/get_balance", get_data)
    http.HandleFunc("/update_balance", update_data)


    source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
    if err != nil {
        log.Fatalf("Unable to create X509 source: %v", err)
    }
    defer source.Close()

    // Allowed SPIFFE ID - Client must be from this trust domain
    clientID := spiffeid.RequireTrustDomainFromString("example.org")

    // Create a `tls.Config` to allow mTLS connections, and verify that presented certificate match the allowed SPIFFE-ID
    tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeMemberOf(clientID))
    server := &http.Server{
        Addr:      ":8443",
        TLSConfig: tlsConfig,
    }

    log.Printf("Start serving API...")
    if err := server.ListenAndServeTLS("", ""); err != nil {
        log.Fatalf("Error on serve: %v", err)
    }

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

func validate_dasvid(data string) (bool, error) {

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


    //validating response
    if !(*result.DasvidExpValidation){

        return false, errors.New("DASVID expired!")
    }

    if !(*result.DasvidSigValidation){

        return false, errors.New("Invalid DASVID signature")
    }

    return true, nil
}


func get_data(w http.ResponseWriter, r *http.Request){

    data := r.FormValue("DASVID")
    validate_result, err := validate_dasvid(data)

    if !(validate_result) {

        log.Fatalf("Invalid DA-SVID: %v", err)
        json.NewEncoder(w).Encode(err)
        return
    }


    //in this example we will consider that only "web" subjects will be able request data
    dasvid_claims := dasvid.ParseTokenClaims(data)
    if dasvid_claims["sub"].(string) != "web"{

        log.Printf("Unauthorized subject workload!")
        json.NewEncoder(w).Encode("Unauthorized subject workload")
        return
    }


    var db *sql.DB

    db, err = sql.Open("sqlite3", "./balances.db")
    if err != nil {

        log.Fatalf("Unable to open database balances.db: %v", err)
    }
    defer db.Close()

    var response Balance
    account_id := r.FormValue("account_id")

    //query database for account id
    query := "select" + account_id + "from balances"
    rows, err := db.Query(query)
    if err != nil {

        log.Fatalf("Unable to query database")
    }
    defer rows.Close()


    for rows.Next() {

        err = rows.Scan(&response.Account_id, &response.Balance)
        if err != nil {

            log.Fatalf("Unable to read rows")
        }
    }
    log.Println("Read %v with balance %v from database", response.Account_id, response.Balance)


    json.NewEncoder(w).Encode(response)

}


func update_data(w http.ResponseWriter, r *http.Request){

    data := r.FormValue("DASVID")
    validate_result, err := validate_dasvid(data)

    if !(validate_result) {

        log.Fatalf("Invalid DA-SVID: %v", err)
        json.NewEncoder(w).Encode(err)
        return
    }


    //in this example we will consider that only "web" subjects will be able request data
    dasvid_claims := dasvid.ParseTokenClaims(data)
    if dasvid_claims["sub"].(string) != "web"{

        log.Printf("Unauthorized subject workload!")
        json.NewEncoder(w).Encode("Unauthorized subject workload")
        return
    }


    var db *sql.DB

    db, err = sql.Open("sqlite3", "./balances.db")
    if err != nil {

        log.Fatalf("Unable to open database balances.db: %v", err)
    }
    defer db.Close()

    var response Balance
    account_id := r.FormValue("account_id")
    new_balance := r.FormValue("balance")

    //query database for account id
    query := "update balances SET balance=" + new_balance + "where account_id=" + account_id
    _, err = db.Exec(query)
    if err != nil {

        log.Fatalf("Unable to update database")
    }


    json.NewEncoder(w).Encode(response)

}
