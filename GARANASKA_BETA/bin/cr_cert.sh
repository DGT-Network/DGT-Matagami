openssl req -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out $1 -keyout $2 -subj "/C=US/ST=New York/L=Brooklyn/O=Example, Inc./OU=IT/CN=api-dgt-c1-1"
