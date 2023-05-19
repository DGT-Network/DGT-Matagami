export TOKEN="-atok $1"

dgt keygen --key-dir /project/peer/keys corp
dgt keygen --key-dir /project/peer/keys corp1
dgt keygen --key-dir /project/peer/keys corp2
dgt keygen --key-dir /project/peer/keys corp3
dgt keygen --key-dir /project/peer/keys admin
dgt keygen --key-dir /project/peer/keys wkey
dgt keygen --key-dir /project/peer/keys wkey1
dgt keygen --key-dir /project/peer/keys wkey2
dgt keygen --key-dir /project/peer/keys wkey3
# make emission
#dec emission  -apk /project/peer/keys/admin.priv -ca /project/peer/keys/corp.pub -ck /project/peer/keys/corp1.pub /project/peer/keys/corp2.pub /project/peer/keys/corp3.pub -ems /project/peer/keys/corp.pub /project/peer/keys/corp1.pub /project/peer/keys/corp2.pub --keyfile /project/peer/keys/corp1.priv
#dec emission  -apk /project/peer/keys/admin.priv -ca /project/peer/keys/corp.pub -ck /project/peer/keys/corp1.pub /project/peer/keys/corp2.pub /project/peer/keys/corp3.pub -ems /project/peer/keys/corp.pub /project/peer/keys/corp1.pub /project/peer/keys/corp2.pub --keyfile /project/peer/keys/corp2.priv
dec emission  -apk /project/peer/keys/admin.priv -ca /project/peer/keys/corp.pub -ck /project/peer/keys/corp1.pub /project/peer/keys/corp2.pub /project/peer/keys/corp3.pub -ems /project/peer/keys/corp.pub /project/peer/keys/corp1.pub /project/peer/keys/corp2.pub --keyfile /project/peer/keys/corp1.priv --corporate_share 20 --minting_share 80 --total_sum 10000000  $TOKEN
dec emission  -apk /project/peer/keys/admin.priv -ca /project/peer/keys/corp.pub -ck /project/peer/keys/corp1.pub /project/peer/keys/corp2.pub /project/peer/keys/corp3.pub -ems /project/peer/keys/corp.pub /project/peer/keys/corp1.pub /project/peer/keys/corp2.pub --keyfile /project/peer/keys/corp2.priv --corporate_share 20 --minting_share 80 --total_sum 10000000 $TOKEN

#dec emission  -apk /project/peer/keys/admin.priv -ca /project/peer/keys/corp.pub -ck /project/peer/keys/corp1.pub /project/peer/keys/corp2.pub /project/peer/keys/corp3.pub
#dec emission  -apk /project/peer/keys/admin.priv -ca /project/peer/keys/corp.pub -ck /project/peer/keys/corp1.pub /project/peer/keys/corp2.pub /project/peer/keys/corp3.pub --keyfile /project/dgt/clusters/c2/dgt1/keys/validator.priv.openssl
# send DEC to wallet for testing
dec faucet /project/peer/keys/wkey.priv 1000 --keyfile /project/peer/keys/validator.priv -pk passkey $TOKEN
dec faucet /project/peer/keys/wkey1.priv 1000 --keyfile /project/peer/keys/validator.priv -pk passkey $TOKEN
# create targets
dec target target-1 1 --keyfile /project/peer/keys/wkey.priv  -g this --tips 0.2 $TOKEN
dec target target-2 2 --keyfile /project/peer/keys/wkey.priv  -g this --tips 0.2 $TOKEN 
dec target target-3 3 --keyfile /project/peer/keys/wkey.priv  -g this --tips 0.2 $TOKEN
dec invoice target-3 123456  1.1 --keyfile /project/peer/keys/wkey.priv $TOKEN
# alias

dec alias trt1@mail.ru --keyfile /project/peer/keys/admin.priv $TOKEN
dec alias trt@mail.ru --keyfile /project/peer/keys/admin.priv $TOKEN
dec alias trt2@mail.ru --keyfile /project/peer/keys/wkey.priv $TOKEN
# account for wkey2
dec account --keyfile /project/peer/keys/wkey2.priv $TOKEN

dec send /project/peer/keys/wkey1.priv trt@mail.ru 1 --keyfile /project/peer/keys/wkey1.priv $TOKEN
dec show trt@mail.ru -tp aliases $TOKEN


# list all objects
dec list $TOKEN
# show off wallets
echo WALLETS
dec list -v -tp accounts $TOKEN
echo EMISSIONS
dec list -v -tp emissions $TOKEN 
echo TARGETS
dec list -v -tp targets $TOKEN
#
