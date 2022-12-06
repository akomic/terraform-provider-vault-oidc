data "vaultoidc_token" "token" {
  oidc_provider = "k8s"
  application   = "myapp"
}
