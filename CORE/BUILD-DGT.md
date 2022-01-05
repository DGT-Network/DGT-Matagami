![Sawtooth=DGT](bgx/images/logo-dgt.png)

Hyperledger Sawtooth-DGT
-------------

Hyperledger Sawtooth-DGT is an enterprise solution for building, deploying, and
running distributed ledgers (also called blockchains). It provides an extremely
modular and flexible platform for implementing transaction-based updates to
shared state between untrusted parties coordinated by consensus algorithms.

.
# install befor start validator
# git clone http://gitlab.ntrlab.ru:83/ntrlab/bgx.git
# sudo apt install docker
# sudo apt install docker.io
# sudo apt install docker-compose
# sudo usermod -aG docker dgt
# sudo apt-get install curl
# sudo curl -L "https://github.com/docker/compose/releases/download/1.23.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
# curl -L "https://github.com/docker/compose/releases/download/1.26.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
# sudo chmod +x /usr/local/bin/docker-compose

To build the requirements to run a validator network, run this command
$ bash upDgtCluster.sh  build
# export COMPOSE_PROJECT_NAME=1 C=c1 N=1 API=8008 COMP=4104 NET=8101 CONS=5051;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml build
Also provided is a docker-compose file which builds a full set of images
with Sawtooth-BGX installed, and only the run-time dependencies installed.

$ docker-compose -f bgx/docker/docker-compose-installed-bgx.yaml build validator

To run a full validator node from the local source.
$ docker-compose -f bgx/docker/docker-compose-net-bgx.yaml up

For running shell-bgx run next bash cmd .
$ docker exec -it shell-dgt-c1-1 bash
For list created tokens run into shell-bgx. 
$ smart-bgt list  --url http://bgx-api:8108
bgt list  --url http://bgx-api:8108
# not in sawtooth shell
$ curl http://localhost:8008/blocks
# smart-bgt init BGX_Token 21fad1db7c1e4f3fb98bb16fcff6942b4b2b9f890196b8754399ebfd74718de1 0xFB2F7C8687F6d86a031D2DE3d51f4c62e83AdA22 20 1 1 --url http://bgx-api-1:8008
# smart-bgt transfer 0236bd0b2f6041338ffe5a2236be89f369ec3094e5247bb40aad3aaa18ff2da395 222 0.1 --url http://rest-api:8008 

# start REST-API 
$ docker-compose -f bgx/docker/docker-compose-rest-api.yaml up 
# make transfer 
$ cd bgs/utils
$ bash transfer.sh 673fcacfb51214e0543b786da79956b541e7d792 4aa37a37b9793a7f3696129d9a367b26fd0b2b1c 1
# create wallet
$ bash create_wallet.sh 673fcacfb51214e0543b786da79956b541e7d792
# get wallet
$ bash get_wallet.sh 673fcacfb51214e0543b786da79956b541e7d792
smart-bgt init BGX_Token 21fad1db7c1e4f3fb98bb16fcff6942b4b2b9f890196b8754399ebfd74718de1 0xFB2F7C8687F6d86a031D2DE3d51f4c62e83AdA22 2000000 1 1 --url http://bgx-api:8018
smart-bgt transfer 0236bd0b2f6041338ffe5a2236be89f369ec3094e5247bb40aad3aaa18ff2da395 028c7e06db3af50a9958390e3e29f166b1cf6198586acf37cde46c8ea54e4a79ea 30 any --url bgx-api:8018
# use orient
docker-compose -f bgx/docker/docker-compose-net-odb-dev-loc.yaml up
# user validator without rust
docker-compose -f bgx/docker/docker-compose-net-bgx-val-pbft.yaml up
# docker-compose -f bgx/docker/docker-compose-net-bgx-val-pbft.yaml 

# for console
#bgx dag show val --url http://bgx-api-2:8009;echo ---;bgx dag show nest --url http://bgx-api-c1-2:8009 -Fjson
#bgx dag show integrity --url http://bgx-api-c1-1:8008;bgx dag show integrity --url http://bgx-api-c1-2:8009
#bgx block list --url http://bgx-api-c1-1:8008;bgx block list --url http://bgx-api-c1-2:8009
#bgt workload --rate 11 -d 5 --url http://bgx-api-c1-1:8008

# for METRICS
cat <<EOF | sudo tee /etc/apt/sources.list.d/influxdata.list
deb https://repos.influxdata.com/ubuntu bionic stable
EOF		
# sudo curl -sL https://repos.influxdata.com/influxdb.key | sudo apt-key add -
# sudo apt-get update
# sudo apt-get -y install telegraf
# sudo cp bgx/etc/telegraf/telegraf.d/sawtooth.conf /etc/telegraf/telegraf.d/bgx.conf 
# sudo systemctl start telegraf
# 
#

# dash
docker-compose -f bgx/docker/docker-compose-dashboard-bgx.yaml up
docker-compose -f bgx/docker/docker-compose-dashboard-bgx2.yaml up
#

# valid
docker-compose -f bgx/docker/docker-compose-net-bgx-val-pbft.yaml up
docker-compose -f bgx/docker/docker-compose-net2-bgx-val-pbft.yaml up

# topology set operations: del, add, cluster, cdel,
# -c <cluster name> -p <peer name> -k <key peer> -l <json with operation params>
dgtset  topology set -c Genesis -p 16 -o map -l '{"AA.aa2":"12345"}' --url http://api-dgt-c1-1:8108
bgxset topology set -c Genesis -p 16 -o del -l "{'024642f5a5214ebc6f8a5e3a189f1bc4d2e877b486bb7362d23837afd19e6ac1e0':{'role':'plink','type':'peer','name':'16'}}" --url http://bgx-api-c1-1:8008
bgxset topology set -c Genesis -p 16 -o add -l "{'024642f5a5214ebc6f8a5e3a189f1bc4d2e877b486bb7362d23837afd19e6ac1e0':{'role':'plink','type':'peer','name':'16'}}" --url http://bgx-api-c1-1:8008
# change leader
bgxset topology set -o lead -c Bgx2 -p 2 --url http://bgx-api-c1-1:8008
#########################################



# nodes
export COMPOSE_PROJECT_NAME=1 N=1 API=8008 COMP=4004 NET=8800 CONS=5050;docker-compose -f bgx/docker/docker-compose-netN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=2 N=2 API=8009 COMP=4006 NET=8801 CONS=5051;docker-compose -f bgx/docker/docker-compose-netN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=3 N=3 API=8010 COMP=4007 NET=8802 CONS=5052;docker-compose -f bgx/docker/docker-compose-netN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=4 N=4 API=8011 COMP=4008 NET=8803 CONS=5053;docker-compose -f bgx/docker/docker-compose-netN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=5 N=5 API=8012 COMP=4009 NET=8804 CONS=5054;docker-compose -f bgx/docker/docker-compose-netN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=6 N=6 API=8013 COMP=4010 NET=8805 CONS=5055;docker-compose -f bgx/docker/docker-compose-netN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=7 N=7 API=8014 COMP=4011 NET=8806 CONS=5056;docker-compose -f bgx/docker/docker-compose-netN-bgx-val-pbft.yaml up
# 
# ssh -i ~/.ssh/aws-bgx.pem ubuntu@bgx
# scp -i ~/.ssh/aws-bgx.pem ubuntu@bgx:/home/ubuntu/log.tgz .
# git checkout -b commands origin/dashboard/commands
# git  pull origin dashboard/commands 
# clusters mode 
# 
# cluster 1
docker-compose -f bgx/docker/docker-compose-netC1-1-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=1 C=c1 N=1 API=8008 COMP=4104 NET=8101 CONS=5051;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=2 C=c1 N=2 API=8009 COMP=4106 NET=8102 CONS=5052;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=3 C=c1 N=3 API=8010 COMP=4107 NET=8103 CONS=5053;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=4 C=c1 N=4 API=8011 COMP=4108 NET=8104 CONS=5054;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=5 C=c1 N=5 API=8012 COMP=4109 NET=8105 CONS=5055;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=6 C=c1 N=6 API=8013 COMP=4110 NET=8106 CONS=5056;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
# cluster 2
export COMPOSE_PROJECT_NAME=21 C=c2 N=1 API=8208 COMP=4204 NET=8201 CONS=5251;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=22 C=c2 N=2 API=8209 COMP=4206 NET=8202 CONS=5252;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=23 C=c2 N=3 API=8210 COMP=4207 NET=8203 CONS=5253;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
# cluster 3
export COMPOSE_PROJECT_NAME=31 C=c3 N=1 API=8308 COMP=4304 NET=8301 CONS=5351;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=32 C=c3 N=2 API=8309 COMP=4306 NET=8302 CONS=5352;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=33 C=c3 N=3 API=8310 COMP=4307 NET=8303 CONS=5353;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
# cluster 4
export COMPOSE_PROJECT_NAME=41 C=c4 N=1 API=8408 COMP=4404 NET=8401 CONS=5451;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=42 C=c4 N=2 API=8409 COMP=4406 NET=8402 CONS=5452;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=43 C=c4 N=3 API=8410 COMP=4407 NET=8403 CONS=5453;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
# cluster 5
export COMPOSE_PROJECT_NAME=51 C=c5 N=1 API=8508 COMP=4504 NET=8501 CONS=5551;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=52 C=c5 N=2 API=8509 COMP=4506 NET=8502 CONS=5552;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=53 C=c5 N=3 API=8510 COMP=4507 NET=8503 CONS=5553;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
# cluster 6
export COMPOSE_PROJECT_NAME=61 C=c6 N=1 API=8608 COMP=4604 NET=8601 CONS=5651;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=62 C=c6 N=2 API=8609 COMP=4606 NET=8602 CONS=5652;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
export COMPOSE_PROJECT_NAME=63 C=c6 N=3 API=8610 COMP=4607 NET=8603 CONS=5653;docker-compose -f bgx/docker/docker-compose-netCN-bgx-val-pbft.yaml up
# start node 1 in cluster 1
bash upDgtCluster.sh -G 1 1 
# stop node 1 in cluster 1
bash downDgtCluster.sh -G 1 1
# start dynamic node local start 
# using real seed endpoint url 
bash upDgtCluster.sh  -G -SC  -S tcp://validator-dgt-c1-1:8101 dyn 1
# using  seed endpoint google url
bash upDgtCluster.sh -G -SC  -S "https://drive.google.com/file/d/1o6SEUvogow432pIKQEL8-EEzNBinzW9R/view?usp=sharing" dyn 1
bash downDgtCluster.sh dyn 1
#########
# telebot
docker-compose -f bgx/docker/docker-compose-telebot-bgx.yaml up
# sudo nmap -sT -p- ntr
# peer ctrl
peers-crtl -C c1 -N 1 -P "2.1,-G" "2.3,-G" "dyn.1,-G -N net0 -S tcp://validator-bgx-c1-1:8101"
# from branch to master
#git checkout -b dag origin/dag 
#git merge -s ours master
#git checkout master
#git merge origin dag
# update peers ports
# export ENDPOINTS="[\"tcp://validator-bgx-c2-1:81\",\"tcp://validator-bgx-c3-1:82\"]"
# composer 
# sudo curl -L "https://github.com/docker/compose/releases/download/1.23.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

# MALI
# http://localhost:8008/peers?mode=ok/ma/ma1/ma2
# NEW CLOUD SERVER ssh -p 7822 dgtca -l root
#
# xcert
xcert set /project/bgx/etc/certificate.json --user /root/.dgt/keys/root.priv
xcert list 
xcert show <pub key>
xcert set /project/bgx/etc/certificate.json --user /project/bgx/clusters/c3/dgt1/keys/validator.priv.openssl
xcert set /project/bgx/etc/certificate.json --before 5 --user /project/bgx/clusters/c3/dgt1/keys/validator.priv.openssl
bash upDgtDashboard.sh -CB openssl
