# Copyright 2021 DGT NETWORK INC © Stanislav Parsov
# START DGT NOTARY
#docker-compose -f docker/docker-compose-notary-dgt.yaml up #-d
mode="up -d"
rmode="up -d"
export PNM="dgt"
export CRYPTO_BACK="bitcoin"
export USER_NOTARY=""
export BOT_TOKEN=""
export LADDR=""
export BON=""
export NREST="OFF"
export SEAL_ADDR="vault-n1:8220"
export REST_API="--url http://api-dgt-c1-1:8108"
export HTTPS_MODE=""
# -BO - telegram bot enable
# -NR  - rest api enable ; -RA <url> - dgt rest api url
# -SA <addr>  - seal addr

while [ -n "$1" ]
do
case "$1" in
-P) shift; export ENDPORT=$1 ;;
-H) shift; export ENDHOST=$1 ;;
-CB) shift; export CRYPTO_BACK=$1 ;;
-UN) shift; export USER_NOTARY="--user-notary $1" ;;
-BT) shift; export BOT_TOKEN="-bt $1" ;;
-BO)  export BON="-bon" ;;
-NR)  export NREST="ON" ;;
-HTTPS) export HTTPS_MODE="--http_ssl";echo "Https mode." ;;
-RA) shift; export REST_API="--url $1" ;;
-SA) shift; export SEAL_ADDR="$1" ;;
-LA) shift; export LADDR="-la $1";echo lead=$LADDR ;;
-IDB) export INFLUXDB="--opentsdb-url";echo "SAVE metrics mode." ;;
--) shift;break ;;
*) break ;;
esac
shift
done
if [[ -e "bin/vault" ]] ; then
      printf "Using [VAULT] from bin/vault\n"
else
     cp docker/vault/vault_1.10.2_linux_amd64.zip bin
     (cd bin;unzip  vault_1.10.2_linux_amd64.zip)   
fi
function upNotary {
  echo "upNotary $#"
  for node in $@;do
    echo "START $node"
    case $node in
        1)
          export COMPOSE_PROJECT_NAME=1 LA=$LADDR C=c1   N=1 V=1 NAPI=8103 COMP=4104 VPORT=8220 CPORT=8221 SADDR=$SEAL_ADDR ONBOT=$BON ;docker-compose -f docker/docker-compose-notary-raft-dgt.yaml $mode 
        ;;                                                        
        2)                                                        
          export COMPOSE_PROJECT_NAME=2 LA=$LADDR C=c1   N=1 V=2 NAPI=8203 COMP=4104 VPORT=8320 CPORT=8321 SADDR=$SEAL_ADDR ONBOT=$BON;docker-compose -f docker/docker-compose-notary-raft-dgt.yaml $rmode
        ;;                                                                          
        3)                                                                          
          export COMPOSE_PROJECT_NAME=3 LA=$LADDR C=c1   N=1 V=3 NAPI=8303 COMP=4104 VPORT=8420 CPORT=8421 SADDR=$SEAL_ADDR ONBOT=$BON ;docker-compose -f docker/docker-compose-notary-raft-dgt.yaml $mode
        ;;                                                                          
        4)                                                                          
          export COMPOSE_PROJECT_NAME=4 LA=$LADDR C=c1   N=1 V=4 NAPI=8403 COMP=4104 VPORT=8520 CPORT=8521 SADDR=$SEAL_ADDR ONBOT=$BON ;docker-compose -f docker/docker-compose-notary-raft-dgt.yaml $mode
        ;;
        build)
         export COMPOSE_PROJECT_NAME=1 LA=$LADDR C=c1   N=1 V=1 NAPI=8203 COMP=4104 VPORT=8200 CPORT=8201 ;docker-compose -f docker/docker-compose-notary-raft-dgt.yaml build 
        ;;
        *)
          echo "Undefined notary."
        ;;
     esac
  done
}

cluster=$1
#shift
case $cluster in
     1)
          echo "Start notary 1"
          if (( $# > 0 ));then
            upNotary $@
          else  
            upNotary $peers
          fi
          ;;
     2)
          echo "Start notary 2"
          if (( $# > 0 ));then
            upNotary $@
          else  
            upNotary $peers
          fi 
          ;;
     3)
          echo "Start notary 3"
          if (( $# > 0 ));then
            upNotary $@
          else  
            upNotary $peers
          fi
          ;; 
      build)
     echo "Start build DGT "
     if (( $# > 0 ));then
       upNotary $@
     else  
       upNotary build
     fi   
     ;;
     all)
          upNotary 1
          upNotary 2
          upNotary 3

          ;;  
     *)
          echo "Enter notary number or all."
          ;;
esac

