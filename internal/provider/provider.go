package provider

import (
	"context"
	"net/http"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
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

func (p *VaultOidcProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{
				MarkdownDescription: "Origin URL of the Vault server. This is a URL with a scheme, a hostname and a port but with no path. May be set via the VAULT_ADDR environment variable.",
				Required:            false,
				Optional:            true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "Vault token that will be used by Terraform to authenticate. May be set via the VAULT_TOKEN environment variable.",
				Required:            false,
				Optional:            true,
			},
			"namespace": schema.StringAttribute{
				MarkdownDescription: "Set the namespace to use. May be set via the VAULT_NAMESPACE environment variable.",
				Optional:            true,
			},
		},
	}
}

type ClientConfig struct {
	Client    *http.Client
	Address   string
	Token     string
	Namespace string
}

func (p *VaultOidcProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var (
		data VaultOidcProviderModel
		ok   bool
	)

	cc := &ClientConfig{
		Client: http.DefaultClient,
	}

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if !data.Address.IsNull() {
		cc.Address = data.Address.ValueString()
	} else if cc.Address, ok = os.LookupEnv("VAULT_ADDR"); !ok {
		resp.Diagnostics.AddError("Provider Error", "address is quired")
		return
	}

	if !data.Token.IsNull() {
		cc.Token = data.Token.ValueString()
	} else if cc.Token, ok = os.LookupEnv("VAULT_TOKEN"); !ok {
		resp.Diagnostics.AddError("Provider Error", "token is quired")
		return
	}

	if !data.Namespace.IsNull() {
		cc.Namespace = data.Namespace.ValueString()
	} else if cc.Namespace, ok = os.LookupEnv("VAULT_NAMESPACE"); !ok {
		cc.Namespace = "admin"
	}

	resp.DataSourceData = cc
	resp.ResourceData = cc
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
