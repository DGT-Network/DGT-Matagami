// Filesystem storage
storage "file" {{
  path    = "{raft_path}"
}}
//storage "inmem" {{}}
// TCP Listener using a self-signed certificate
listener "tcp" {{
  address     = "{addr}"
  tls_disable = true
}}
disable_mlock = true
