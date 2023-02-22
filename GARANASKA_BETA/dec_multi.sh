dec account -pk /project/peer/keys/wkey.priv /project/peer/keys/wkey1.priv /project/peer/keys/wkey3.priv -sm 2 --keyfile /project/peer/keys/wkey3.priv
dec faucet /project/peer/keys/wkey3.priv 1000 --keyfile /project/peer/keys/validator.priv -pk passkey
dec send /project/peer/keys/wkey3.pub /project/peer/keys/corp.pub 1 --keyfile /project/peer/keys/wkey1.priv -tid trans
dec send /project/peer/keys/wkey3.pub /project/peer/keys/corp.pub 1 --keyfile /project/peer/keys/wkey3.priv -tid trans
dec show /project/peer/keys/corp.pub
