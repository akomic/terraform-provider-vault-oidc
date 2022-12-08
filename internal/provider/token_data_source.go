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
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
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
	client      *ClientConfig
	Application *K8SClientResponse
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

func (d *TokenDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "Token data source",

		Attributes: map[string]schema.Attribute{
			"oidc_provider": schema.StringAttribute{
				MarkdownDescription: "OIDC provider",
				Required:            true,
				Optional:            false,
			},
			"application": schema.StringAttribute{
				MarkdownDescription: "Application",
				Required:            true,
				Optional:            false,
			},
			"response_type": schema.StringAttribute{
				MarkdownDescription: "Response Type, default 'code'",
				Optional:            true,
			},
			"redirect_uri": schema.StringAttribute{
				MarkdownDescription: "Redirect URI, default http://localhost:8000",
				Optional:            true,
			},
			"scope": schema.StringAttribute{
				MarkdownDescription: "Scopes, default openid k8s-user k8s-groups",
				Optional:            true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "Token",
				Computed:            true,
				Sensitive:           true,
			}},
	}
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

func (d *TokenDataSource) GetApplication(ctx context.Context, data *TokenDataSourceModel) (err error) {
	applicationURI := fmt.Sprintf("%s/v1/%s/identity/oidc/client/%s", d.client.Address, d.client.Namespace, data.Application.ValueString())

	request, err := http.NewRequest("GET", applicationURI, nil)
	if err != nil {
		return fmt.Errorf("unable to prepare request %s: err: %v", applicationURI, err)
	}

	// request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("X-Vault-Request", "true")
	request.Header.Add("X-Vault-Token", d.client.Token)

	applicationResponse, err := d.client.Client.Do(request)
	if err != nil {
		return fmt.Errorf("unable to get application against %s: err: %v", applicationURI, err)
	}

	body, err := io.ReadAll(applicationResponse.Body)
	if err != nil {
		return fmt.Errorf("unable to handle application body response %s: err: %v", applicationURI, err)
	}

	tflog.Trace(ctx, fmt.Sprintf("GET application %s: %s", applicationURI, body))

	var applicationResp *K8SClientResponse
	err = json.Unmarshal(body, &applicationResp)
	if err != nil {
		return fmt.Errorf("unable to unmarshall body response for application: err: %v", err)
	}

	if applicationResp.Data.ClientID == "" || applicationResp.Data.ClientSecret == "" || applicationResp.Error != "" || len(applicationResp.Errors) > 0 {
		return fmt.Errorf("invalid application response: Error: %s Desc: %s Errors: %v", applicationResp.Error, applicationResp.ErrorDescription, applicationResp.Errors)
	}

	d.Application = applicationResp
	return nil
}

func (d *TokenDataSource) GetAuthorization(ctx context.Context, data *TokenDataSourceModel) (authorizationResp *K8SAuthResponse, err error) {
	providerURI := fmt.Sprintf("%s/v1/%s/identity/oidc/provider/%s", d.client.Address, d.client.Namespace, data.OidcProvider.ValueString())

	state, err := random32()
	if err != nil {
		return authorizationResp, fmt.Errorf("could not generate random state: %v", err)
	}

	nonce, err := random32()
	if err != nil {
		return authorizationResp, fmt.Errorf("could not generate random nonce: %v", err)
	}

	if data.Scope.IsNull() {
		data.Scope = types.StringValue("openid k8s-user k8s-groups")
	}
	tflog.Trace(ctx, fmt.Sprintf("SCOPE: %s", data.Scope))

	if data.ResponseType.IsNull() {
		data.ResponseType = types.StringValue("code")
	}
	tflog.Trace(ctx, fmt.Sprintf("RESPONSETYPE: %s", data.ResponseType))

	if data.RedirectURI.IsNull() {
		data.RedirectURI = types.StringValue("http://localhost:8000")
	}
	tflog.Trace(ctx, fmt.Sprintf("REDIRECTURI: %s", data.RedirectURI))

	values := &url.Values{
		"scope":         {data.Scope.ValueString()},
		"response_type": {data.ResponseType.ValueString()},
		"client_id":     {d.Application.Data.ClientID},
		"redirect_uri":  {data.RedirectURI.ValueString()},
		"state":         {state},
		"nonce":         {nonce},
	}

	request, err := http.NewRequest("POST", fmt.Sprintf("%s/authorize", providerURI), strings.NewReader(values.Encode()))
	if err != nil {
		return authorizationResp, fmt.Errorf("unable to prepare request %s/authorize: err: %v", providerURI, err)
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("X-Vault-Request", "true")
	request.Header.Add("X-Vault-Token", d.client.Token)

	authorizeResponse, err := d.client.Client.Do(request)
	if err != nil {
		return authorizationResp, fmt.Errorf("unable to get authorization against %s/authorize: err: %v", providerURI, err)
	}

	body, err := io.ReadAll(authorizeResponse.Body)
	if err != nil {
		return authorizationResp, fmt.Errorf("unable to handle token body response %s/authorize: err: %v", providerURI, err)
	}

	tflog.Trace(ctx, fmt.Sprintf("POST /authorize: %s", body))

	err = json.Unmarshal(body, &authorizationResp)
	if err != nil {
		return authorizationResp, fmt.Errorf("unable to unmarshall body response /authorize: err: %v", err)
	}

	if authorizationResp.Error != "" || authorizationResp.Errors != "" {
		return authorizationResp, fmt.Errorf("invalid authorize response: Error: %s Desc: %s Errors: %s", authorizationResp.Error, authorizationResp.ErrorDescription, authorizationResp.Errors)
	}

	if state != authorizationResp.State {
		return authorizationResp, fmt.Errorf("invalid state returned %s != %s", state, authorizationResp.State)
	}

	return authorizationResp, nil
}

func (d *TokenDataSource) GetToken(ctx context.Context, data *TokenDataSourceModel, code string) (tokenResp *K8STokenResponse, err error) {
	providerURI := fmt.Sprintf("%s/v1/%s/identity/oidc/provider/%s", d.client.Address, d.client.Namespace, data.OidcProvider.ValueString())

	values := &url.Values{
		"code":         {code},
		"grant_type":   {"authorization_code"},
		"redirect_uri": {data.RedirectURI.ValueString()},
	}

	request, err := http.NewRequest("POST", fmt.Sprintf("%s/token", providerURI), strings.NewReader(values.Encode()))
	if err != nil {
		return tokenResp, fmt.Errorf("unable to prepare request %s/token: err: %v", providerURI, err)
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(d.Application.Data.ClientID, d.Application.Data.ClientSecret)

	tokenResponse, err := d.client.Client.Do(request)
	if err != nil {
		return tokenResp, fmt.Errorf("unable to get token against %s/token: err: %v", providerURI, err)
	}

	body, err := io.ReadAll(tokenResponse.Body)
	if err != nil {
		return tokenResp, fmt.Errorf("unable to handle token body response %s/token: err: %v", providerURI, err)
	}

	tflog.Trace(ctx, fmt.Sprintf("POST /token: %s", body))

	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return tokenResp, fmt.Errorf("unable to unmarshall body response /token: err: %v", err)
	}

	if tokenResp.Error != "" || tokenResp.Errors != "" {
		return tokenResp, fmt.Errorf("invalid token response: Error: %s Desc: %s Errors: %s", tokenResp.Error, tokenResp.ErrorDescription, tokenResp.Errors)
	}

	return tokenResp, nil
}

func (d *TokenDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data TokenDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	err := d.GetApplication(ctx, &data)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", err.Error())
		return
	}

	authorizationResp, err := d.GetAuthorization(ctx, &data)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", err.Error())
		return
	}

	tokenResp, err := d.GetToken(ctx, &data, authorizationResp.Code)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", err.Error())
		return
	}

	data.Token = types.StringValue(tokenResp.IDToken)

	tflog.Trace(ctx, fmt.Sprintf("output %+v", data))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
