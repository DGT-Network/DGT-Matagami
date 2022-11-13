dgt keygen mkey --key-dir /tmp -cb openssl
notary crt 12345678 --user /tmp/mkey.priv #notary crt /project/dgt/etc/certificate.json --user 12345678
notary wallet /tmp/mkey.priv --did "did:notary:30563010:12345678"
notary wallets "did:notary:30563010:12345678"
notary role myrole "did:notary:30563010:12345678" --keyfile /tmp/mkey.priv
notary roles "did:notary:30563010:12345678"
notary target mytarget "did:notary:30563010:12345678" 100 --invoice --keyfile /tmp/mkey.priv
notary goods  "did:notary:30563010:12345678"

