# STOP DGT NOTARY
# docker-compose -f docker/docker-compose-notary-dgt.yaml down


mode="down" #"up -d"
export PNM="dgt"
export CRYPTO_BACK="bitcoin"
export LADDR=""
export BON=""
export NREST="OFF"
export SEAL_ADDR="vault-n1:8220"


while [ -n "$1" ]
do
case "$1" in
-P) shift; export ENDPORT=$1 ;;
-H) shift; export ENDHOST=$1 ;;
-CB) shift; export CRYPTO_BACK=$1 ;;
-IDB) export INFLUXDB="--opentsdb-url";echo "SAVE metrics mode." ;;
--) shift;break ;;
*) break ;;
esac
shift
done

function downNotary {
  echo "downNotary $#"
  for node in $@;do
    echo "STOP $node"
    case $node in
        1)
          export COMPOSE_PROJECT_NAME=1 LA=$LADDR C=c1   N=1 V=1 NAPI=8103 COMP=4104 VPORT=8220 CPORT=8221 SADDR=$SEAL_ADDR ONBOT=$BON ;docker-compose -f docker/docker-compose-notary-raft-dgt.yaml $mode
        ;;                                                        
        2)     
          export COMPOSE_PROJECT_NAME=2 LA=$LADDR C=c1   N=1 V=2 NAPI=8203 COMP=4104 VPORT=8320 CPORT=8321 SADDR=$SEAL_ADDR ONBOT=$BON;docker-compose -f docker/docker-compose-notary-raft-dgt.yaml $mode                                                   
        ;;                                                        
        3)                                                        
          export COMPOSE_PROJECT_NAME=3 LA=$LADDR C=c1   N=1 V=3 NAPI=8303 COMP=4104 VPORT=8420 CPORT=8421 ;docker-compose -f docker/docker-compose-notary-raft-dgt.yaml $mode
        ;;                                                        
        4)                                                        
          export COMPOSE_PROJECT_NAME=4 LA=$LADDR C=c1   N=1 V=4 NAPI=8403 COMP=4104 VPORT=8520 CPORT=8521 ;docker-compose -f docker/docker-compose-notary-raft-dgt.yaml $mode
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
     1|genesis)
          echo "Stop notary genesis"
          if (( $# > 0 ));then
            downNotary $@
          else  
            downNotary $peers
          fi
          ;;
     2)
          echo "Stop notary 2"
          if (( $# > 0 ));then
            downNotary $@
          else  
            downNotary $peers
          fi 
          ;;
     3)
          echo "Stop notary 3"
          if (( $# > 0 ));then
            downNotary $@
          else  
            downNotary $peers
          fi
          ;; 
      build)
     echo "Stop build DGT NOTARY"
     if (( $# > 0 ));then
       buildCluster $@
     else  
       buildCluster all
     fi   
     ;;
     all)
          downNotary 1
          downNotary 2
          downNotary 3

          ;;  
     *)
          echo "Enter notary number or all."
          ;;
esac


