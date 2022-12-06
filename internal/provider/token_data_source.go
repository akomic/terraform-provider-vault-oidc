package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces
var _ datasource.DataSource = &TokenDataSource{}

func NewTokenDataSource() datasource.DataSource {
	return &TokenDataSource{}
}

// TokenDataSource defines the data source implementation.
type TokenDataSource struct {
	client *ClientConfig
}

// TokenDataSourceModel describes the data source data model.
type TokenDataSourceModel struct {
	OidcProvider types.String `tfsdk:"oidc_provider"`
	Application  types.String `tfsdk:"application"`
	ResponseType types.String `tfsdk:"response_type"`
	RedirectURI  types.String `tfsdk:"redirect_uri"`
	Scope        types.String `tfsdk:"scope"`
	Token        types.String `tfsdk:"token"`
}

func (d *TokenDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_token"
}

func (d *TokenDataSource) GetSchema(ctx context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "Token data source",

		Attributes: map[string]tfsdk.Attribute{
			"oidc_provider": {
				MarkdownDescription: "OIDC provider",
				Required:            true,
				Optional:            false,
				Type:                types.StringType,
			},
			"application": {
				MarkdownDescription: "Application",
				Required:            true,
				Optional:            false,
				Type:                types.StringType,
			},
			"response_type": {
				MarkdownDescription: "Response Type, default 'code'",
				Optional:            true,
				Type:                types.StringType,
			},
			"redirect_uri": {
				MarkdownDescription: "Redirect URI, default http://localhost:8000",
				Optional:            true,
				Type:                types.StringType,
			},
			"scope": {
				MarkdownDescription: "Scopes",
				Optional:            true,
				Type:                types.StringType,
			},
			"token": {
				MarkdownDescription: "Token",
				Computed:            true,
				Sensitive:           true,
				Type:                types.StringType,
			}},
	}, nil
}

func (d *TokenDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*ClientConfig)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *ClientConfig, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}

type K8SAuthResponse struct {
	Code             string `json:"code"`
	State            string `json:"state"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	Errors           string `json:"errors,omitempty"`
}

type K8STokenResponse struct {
	Tokentype        string `json:"token_type"`
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	ExpiresIn        int64  `json:"expires_in"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	Errors           string `json:"errors,omitempty"`
}

type K8SClientResponse struct {
	Data struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	} `json:"data"`
	Error            string   `json:"error,omitempty"`
	ErrorDescription string   `json:"error_description,omitempty"`
	Errors           []string `json:"errors,omitempty"`
}

func (d *TokenDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data TokenDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	applicationURI := fmt.Sprintf("%s/v1/%s/identity/oidc/client/%s", d.client.Address, d.client.Namespace, data.Application.ValueString())

	request, err := http.NewRequest("GET", applicationURI, nil)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to prepare request %s: err: %v", applicationURI, err))
		return
	}

	// request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("X-Vault-Request", "true")
	request.Header.Add("X-Vault-Token", d.client.Token)

	applicationResponse, err := d.client.Client.Do(request)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to get application against %s: err: %v", applicationURI, err))
		return
	}

	body, err := io.ReadAll(applicationResponse.Body)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to handle application body response %s: err: %v", applicationURI, err))
		return
	}

	tflog.Trace(ctx, fmt.Sprintf("GET application %s: %s", applicationURI, body))

	var applicationResp K8SClientResponse
	err = json.Unmarshal(body, &applicationResp)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to unmarshall body response for application: err: %v", err))
		return
	}

	if applicationResp.Data.ClientID == "" || applicationResp.Data.ClientSecret == "" || applicationResp.Error != "" || len(applicationResp.Errors) > 0 {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("invalid application response: Error: %s Desc: %s Errors: %v", applicationResp.Error, applicationResp.ErrorDescription, applicationResp.Errors))
		return
	}

	state, err := random32()
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("could not generate random state: %w", err))
		return
	}

	nonce, err := random32()
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("could not generate random nonce: %w", err))
		return
	}

	providerURI := fmt.Sprintf("%s/v1/%s/identity/oidc/provider/%s", d.client.Address, d.client.Namespace, data.OidcProvider.ValueString())

	scope := "openid k8s-user k8s-groups"
	if !data.Scope.IsNull() {
		scope = data.Scope.ValueString()
	}

	responseType := "code"
	if !data.ResponseType.IsNull() {
		scope = data.ResponseType.ValueString()
	}

	redirectURI := "http://localhost:8000"
	if !data.RedirectURI.IsNull() {
		scope = data.RedirectURI.ValueString()
	}

	values := &url.Values{
		"scope":         {scope},
		"response_type": {responseType},
		"client_id":     {applicationResp.Data.ClientID},
		"redirect_uri":  {redirectURI},
		"state":         {state},
		"nonce":         {nonce},
	}

	request, err = http.NewRequest("POST", fmt.Sprintf("%s/authorize", providerURI), strings.NewReader(values.Encode()))
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to prepare request %s/authorize: err: %v", providerURI, err))
		return
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("X-Vault-Request", "true")
	request.Header.Add("X-Vault-Token", d.client.Token)

	authorizeResponse, err := d.client.Client.Do(request)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to get authorization against %s/authorize: err: %v", providerURI, err))
		return
	}

	body, err = io.ReadAll(authorizeResponse.Body)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to handle token body response %s/authorize: err: %v", providerURI, err))
		return
	}

	tflog.Trace(ctx, fmt.Sprintf("POST /authorize: %s", body))

	var r K8SAuthResponse
	err = json.Unmarshal(body, &r)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to unmarshall body response /authorize: err: %v", err))
		return
	}

	if r.Error != "" || r.Errors != "" {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("invalid authorize response: Error: %s Desc: %s Errors: %s", r.Error, r.ErrorDescription, r.Errors))
		return
	}

	if state != r.State {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("invalid state returned %s != %s", state, r.State))
		return
	}

	values = &url.Values{
		"code":         {r.Code},
		"grant_type":   {"authorization_code"},
		"redirect_uri": {redirectURI},
	}

	request, err = http.NewRequest("POST", fmt.Sprintf("%s/token", providerURI), strings.NewReader(values.Encode()))
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to prepare request %s/token: err: %v", providerURI, err))
		return
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(applicationResp.Data.ClientID, applicationResp.Data.ClientSecret)

	tokenResponse, err := d.client.Client.Do(request)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to get token against %s/token: err: %v", providerURI, err))
		return
	}

	body, err = io.ReadAll(tokenResponse.Body)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to handle token body response %s/token: err: %v", providerURI, err))
		return
	}

	tflog.Trace(ctx, fmt.Sprintf("POST /token: %s", body))

	var tokenResp *K8STokenResponse
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("unable to unmarshall body response /token: err: %v", err))
		return
	}

	if tokenResp.Error != "" || tokenResp.Errors != "" {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("invalid token response: Error: %s Desc: %s Errors: %s", tokenResp.Error, tokenResp.ErrorDescription, tokenResp.Errors))
		return
	}

	// If applicable, this is a great opportunity to initialize any necessary
	// provider client data and make a call using it.
	// httpResp, err := d.client.Do(httpReq)
	// if err != nil {
	//     resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read token, got error: %s", err))
	//     return
	// }

	// For the purposes of this token code, hardcoding a response value to
	// save into the Terraform state.
	// data.Id = types.StringValue("token-id")

	data.Token = types.StringValue(tokenResp.IDToken)

	tflog.Trace(ctx, fmt.Sprintf("output %+v", data))
	// Write logs using the tflog package
	// Documentation: https://terraform.io/plugin/log
	// tflog.Trace(ctx, "read a data source")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
