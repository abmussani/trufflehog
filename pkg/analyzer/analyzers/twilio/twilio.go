package twilio

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/fatih/color"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/pb/analyzerpb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzerpb.AnalyzerType { return analyzerpb.AnalyzerType_Twilio }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	info, err := AnalyzePermissions(a.Cfg, credInfo["key"])
	if err != nil {
		return nil, err
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	if info.VerifyJson.Code == INVALID_CREDENTIALS {
		return nil
	}

	result := &analyzers.AnalyzerResult{
		AnalyzerType: analyzerpb.AnalyzerType_Twilio,
		Metadata: map[string]any{
			"verify_json":         info.VerifyJson,
			"account_status_code": info.AccountStatusCode,
		},
	}

	if info.VerifyJson.Code == AUTHENTICATED_NO_PERMISSION {
		result.Bindings = getRestrictedKeyBindings()
		return result
	}

	result.Bindings = getPermissionBindings(info.AccountStatusCode)
	return result
}

// getPermissionBindings returns the permissions based on the status code
// 200 means the key is main, 401 means the key is standard
func getPermissionBindings(statusCode int) []analyzers.Binding {

	if statusCode != 200 && statusCode != 401 {
		return []analyzers.Binding{}
	}

	if statusCode == 401 {
		return []analyzers.Binding{
			{
				Resource: analyzers.Resource{
					Name:               "All EXCEPT key management and account/subaccount configuration.",
					FullyQualifiedName: "All EXCEPT key management and account/subaccount configuration.",
					Type:               "all",
					Metadata:           nil,
					Parent:             nil,
				},
				Permission: analyzers.Permission{
					Value:       "All EXCEPT key management and account/subaccount configuration.",
					AccessLevel: "standard",
					Parent:      nil,
				},
			},
		}
	}

	return []analyzers.Binding{
		{
			Resource: analyzers.Resource{
				Name:               "All",
				FullyQualifiedName: "All",
				Type:               "all",
				Metadata:           nil,
				Parent:             nil,
			},
			Permission: analyzers.Permission{
				Value:       "All",
				AccessLevel: "main (admin)",
				Parent:      nil,
			},
		},
	}
}

// getRestrictedKeyBindings returns the bindings for a restricted key
// this is a temporary measure since the restricted key type is still in beta
func getRestrictedKeyBindings() []analyzers.Binding {

	return []analyzers.Binding{
		{
			Resource: analyzers.Resource{
				Name:               "All",
				FullyQualifiedName: "All",
				Type:               "all",
				Metadata:           nil,
				Parent:             nil,
			},
			Permission: analyzers.Permission{
				Value:       "restricted",
				AccessLevel: "restricted",
				Parent:      nil,
			},
		},
	}
}

type VerifyJSON struct {
	Code int `json:"code"`
}

type SecretInfo struct {
	VerifyJson        VerifyJSON
	AccountStatusCode int
}

const (
	AUTHENTICATED_NO_PERMISSION = 70051
	INVALID_CREDENTIALS         = 20003
)

// splitKey splits the key into SID and Secret
func splitKey(key string) (string, string, error) {
	split := strings.Split(key, ":")
	if len(split) != 2 {
		return "", "", errors.New("key must be in the format SID:Secret")
	}
	return split[0], split[1], nil
}

// getAccountsStatusCode returns the status code from the Accounts endpoint
// this is used to determine whether the key is scoped as main or standard, since standard has no access here.
func getAccountsStatusCode(cfg *config.Config, sid string, secret string) (int, error) {
	// create http client
	client := analyzers.NewAnalyzeClient(cfg)

	// create request
	req, err := http.NewRequest("GET", "https://api.twilio.com/2010-04-01/Accounts", nil)
	if err != nil {
		return 0, err
	}

	// add query params
	q := req.URL.Query()
	q.Add("FriendlyName", "zpoOnD08HdLLZGFnGUMTxbX3qQ1kS")
	req.URL.RawQuery = q.Encode()

	// add basicAuth
	req.SetBasicAuth(sid, secret)

	// send request
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// getVerifyServicesStatusCode returns the status code and the JSON response from the Verify Services endpoint
// only the code value is captured in the JSON response and this is only shown when the key is invalid or has no permissions
func getVerifyServicesStatusCode(cfg *config.Config, sid string, secret string) (VerifyJSON, error) {
	var verifyJSON VerifyJSON

	// create http client
	client := analyzers.NewAnalyzeClient(cfg)

	// create request
	req, err := http.NewRequest("GET", "https://verify.twilio.com/v2/Services", nil)
	if err != nil {
		return verifyJSON, err
	}

	// add query params
	q := req.URL.Query()
	q.Add("FriendlyName", "zpoOnD08HdLLZGFnGUMTxbX3qQ1kS")
	req.URL.RawQuery = q.Encode()

	// add basicAuth
	req.SetBasicAuth(sid, secret)

	// send request
	resp, err := client.Do(req)
	if err != nil {
		return verifyJSON, err
	}
	defer resp.Body.Close()

	// read response
	if err := json.NewDecoder(resp.Body).Decode(&verifyJSON); err != nil {
		return verifyJSON, err
	}

	return verifyJSON, nil
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	sid, secret, err := splitKey(key)
	if err != nil {
		return nil, err
	}

	verifyJSON, err := getVerifyServicesStatusCode(cfg, sid, secret)
	if err != nil {
		return nil, err
	}

	statusCode, err := getAccountsStatusCode(cfg, sid, secret)
	if err != nil {
		return nil, err
	}

	return &SecretInfo{
		VerifyJson:        verifyJSON,
		AccountStatusCode: statusCode,
	}, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	// ToDo: Add in logging
	if cfg.LoggingEnabled {
		color.Red("[x] Logging is not supported for this analyzer.")
		return
	}

	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error: %s", err.Error())
		return
	}

	if info.VerifyJson.Code == INVALID_CREDENTIALS {
		color.Red("[x] Invalid Twilio API Key")
		return
	}

	if info.VerifyJson.Code == AUTHENTICATED_NO_PERMISSION {
		printRestrictedKeyMsg()
		return
	}

	printPermissions(info.AccountStatusCode)
}

// printPermissions prints the permissions based on the status code
// 200 means the key is main, 401 means the key is standard
func printPermissions(statusCode int) {

	if statusCode != 200 && statusCode != 401 {
		color.Red("[x] Invalid Twilio API Key")
		return
	}

	color.Green("[!] Valid Twilio API Key\n")
	color.Green("[i] Expires: Never")

	if statusCode == 401 {
		color.Yellow("[i] Key type: Standard")
		color.Yellow("[i] Permissions: All EXCEPT key management and account/subaccount configuration.")

	} else if statusCode == 200 {
		color.Green("[i] Key type: Main (aka Admin)")
		color.Green("[i] Permissions: All")
	}
}

// printRestrictedKeyMsg prints the message for a restricted key
// this is a temporary measure since the restricted key type is still in beta
func printRestrictedKeyMsg() {
	color.Green("[!] Valid Twilio API Key\n")
	color.Green("[i] Expires: Never")
	color.Yellow("[i] Key type: Restricted")
	color.Yellow("[i] Permissions: Limited")
	fmt.Println("[*] Note: Twilio is rolling out a Restricted API Key type, which provides fine-grained control over API endpoints. Since it's still in a Public Beta, this has not been incorporated into this tool.")
}
