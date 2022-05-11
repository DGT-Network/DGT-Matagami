// Enable UI
ui = true

// Filesystem storage
storage "file" {
  path    = "/vault/data"
}

// TCP Listener using a self-signed certificate
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
  //tls_cert_file = "localhost.cert"
  //tls_key_file = "localhost.key"
}
