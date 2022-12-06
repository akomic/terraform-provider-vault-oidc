package provider

import (
	"context"
	"net/http"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure VaultOidcProvider satisfies various provider interfaces.
var _ provider.Provider = &VaultOidcProvider{}
var _ provider.ProviderWithMetadata = &VaultOidcProvider{}

// VaultOidcProvider defines the provider implementation.
type VaultOidcProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// VaultOidcProviderModel describes the provider data model.
type VaultOidcProviderModel struct {
	Address   types.String `tfsdk:"address"`
	Token     types.String `tfsdk:"token"`
	Namespace types.String `tfsdk:"namespace"`
}

func (p *VaultOidcProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "vaultoidc"
	resp.Version = p.version
}

func (p *VaultOidcProvider) GetSchema(ctx context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"address": {
				MarkdownDescription: "Origin URL of the Vault server. This is a URL with a scheme, a hostname and a port but with no path. May be set via the VAULT_ADDR environment variable.",
				Required:            false,
				Optional:            true,
				Type:                types.StringType,
			},
			"token": {
				MarkdownDescription: "Vault token that will be used by Terraform to authenticate. May be set via the VAULT_TOKEN environment variable.",
				Required:            false,
				Optional:            true,
				Type:                types.StringType,
			},
			"namespace": {
				MarkdownDescription: "Set the namespace to use. May be set via the VAULT_NAMESPACE environment variable.",
				Optional:            true,
				Type:                types.StringType,
			},
		},
	}, nil
}

type ClientConfig struct {
	Client    *http.Client
	Address   string
	Token     string
	Namespace string
}

func (p *VaultOidcProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data VaultOidcProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	address := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	namespace := ""
	if value, ok := os.LookupEnv("VAULT_NAMESPACE"); ok {
		namespace = value
	} else {
		namespace = "admin"
	}

	if !data.Address.IsNull() {
		address = data.Address.ValueString()
	}

	if !data.Token.IsNull() {
		token = data.Token.ValueString()
	}

	if !data.Namespace.IsNull() {
		namespace = data.Namespace.ValueString()
	}

	if address == "" {
		resp.Diagnostics.AddError("Provider Error", "address is quired")
		return
	}

	if token == "" {
		resp.Diagnostics.AddError("Provider Error", "token is quired")
		return
	}

	// Configuration values are now available.
	// if data.Endpoint.IsNull() { /* ... */ }

	// Example client configuration for data sources and resources
	client := http.DefaultClient
	resp.DataSourceData = &ClientConfig{
		Client:    client,
		Address:   address,
		Token:     token,
		Namespace: namespace,
	}
	resp.ResourceData = &ClientConfig{
		Client:    client,
		Address:   address,
		Token:     token,
		Namespace: namespace,
	}
}

func (p *VaultOidcProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

func (p *VaultOidcProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewTokenDataSource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &VaultOidcProvider{
			version: version,
		}
	}
}
