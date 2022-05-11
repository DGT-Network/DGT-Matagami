storage "raft" {{
    path    = "{raft_path}"
    node_id = "{raft_id}"
    retry_join {{                               
      leader_api_addr = "{lead_addr}"
    }}                                          
  }}
  listener "tcp" {{
    address = "{addr}"
    cluster_address = "{clust_addr}"
    tls_disable = true
  }}
  seal "transit" {{
    address            = "{seal_addr}"
    // token is read from VAULT_TOKEN env
    token              = "{seal_token}"
    disable_renewal    = "false"

    // Key configuration
    key_name           = "unseal_key"
    mount_path         = "transit/"
  }}
  disable_mlock = true
  cluster_addr = "http://{clust_addr}"
