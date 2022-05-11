path "secret/*" {
    capabilities = ["create", "update", "delete", "list", "read"]
}
path "secret/data/" {
    capabilities = ["create", "update", "delete", "list", "read"]
}


