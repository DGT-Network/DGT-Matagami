#!/bin/bash
# DGT SERVICE CONTROL
#
FILE_ENV=./.env.dgt
source $FILE_ENV

COMPOSE=docker-compose
# get name and operation
SNM=$1
shift
CMD=$1
shift

if ! command -v $COMPOSE &> /dev/null
then
    echo "$COMPOSE could not be found"
    echo "Use docker with option compose"
    COMPOSE="docker compose"
fi
declare -A DEF_PARAMS=(
[DAG_BRANCH]="6"
[MAX_PEER]="70"
[DBMODE]="metrics" 
[DBPORT]="8086"
[ENDHOST]=""
[ENDPOINTS]=""
[SEEDS]=""
[COMP_URL]="tcp://validator-dgt-c1-1:4104"

)
#FCOMPOSE="docker-compose-netCN-dgt-dec-ci.yaml"
#DGT_PARAM_LIST=${DGT_PARAMS[@]} #(PEER CLUST NODE GENESIS SINGLE PCONTROL PEERING NETWORK METRIC SIGNED INFLUXDB DBHOST DBUSER DBPASS PNM KYC CRYPTO_BACK HTTPS_MODE ACCESS_TOKEN)
declare -A MODES_HELP=(
 [dynamic]="Set/reset peer in dynamic mode"
 [access]="Set/reset token access mode"
 [https]="Set/reset https mode"
 [genesis]="Set/reset genesis mode for peer"
 [signed]="Set/reset signed consensus mode for peer"
 [metric]="Set/reset metric mode for peer"

)
# etc/dgt.net.static etc/dgt.net.dyn
# 
declare -A CONFS_SRC=(
 [cert]="etc/certificate.json"
 [oauth]="etc/oauth_conf.json"
 [gate]="etc/entry_points.json"
 [net]="etc/dgt.net.map"

)
declare -A CONFS_HELP=(
 [cert]="Show peer certificate"
 [oauth]="Show auth config"
 [gate]="Show gateway config"
 [net]="Show network config"

)

declare -A CMDS_HELP=(
 [build]="Build or rebuild services: ./dgt_control.sh c1_1 build validator-dgt"
 [up]="Create and start DGT containers: ./dgt_control.sh c1_1 up [-d]"
 [down]="Stop and remove DGT containers, networks, images, and volumes: ./dgt_control.sh c1_1 down"
 [start]="Start DGT services: ./dgt_control.sh c1_1 start"
 [stop]="Stop DGT services: ./dgt_control.sh c1_1 stop"
 [restart]="Restart DGT services: ./dgt_control.sh c1_1 restart"
 [list]="Print DGT peer's params: ./dgt_control.sh dgt list [-v]"
 [show]="DGT peer params: ./dgt_control.sh c1_2 show"
 [edit]="Edit DGT peer params: ./dgt_control.sh c1_1 edit [<param name>]"
 [add]="Add new DGT peer: ./dgt_control.sh c4_1 add"
 [del]="Drop peer declaration: ./dgt_control.sh c4_1 del"
 [copy]="Make peer copy: ./dgt_control.sh c1_1 copy <new peer name>"
 [mode]="Change peer mode: ./dgt_control.sh c1_1 <mode name>"
 [shell]="Enter into peer shell: ./dgt_control.sh c1_1 shell"
 [token]="Generate access token: ./dgt_control.sh c1_1 token"
 [dec]="Run dec commands: ./dgt_control.sh c1_1 dec list"
 [run]="Run dgt commands: ./dgt_control.sh c1_1 run bgt list"
 [ps]="List containers: ./dgt_control.sh c1_1 ps [-q/--services]"

)
if [ ! -v FCOMPOSE ]; then
FCOMPOSE="docker/docker-compose-netCN-dgt-dec-ci.yaml"
fi
if [ ! -v DASH_FCOMP ]; then
DASH_FCOMP="docker/docker-compose-dash-dgt-ci.yaml"
fi
if [ ! -v GRAF_FCOMP ]; then
GRAF_FCOMP="docker/docker-compose-grafana-dgt.yaml"
fi
if [ ! -v NOTA_FCOMP ]; then
NOTA_FCOMP="docker/docker-compose-notary-raft-dgt.yaml"
fi
if [ ! -v DEVEL_FCOMP ]; then
DEVEL_FCOMP="docker/docker-compose-devel.yaml"
fi
# all known type of list
if [ ! -v DEVEL_LIST ]; then
DEVEL_LIST=()
fi
if [ ! -v CLUSTER_LIST ]; then
CLUSTER_LIST=()
fi

if [ ! -v DGT_PARAMS ]; then
DGT_PARAMS=(PEER CLUST NODE API COMP NET CONS GENESIS SINGLE DAG_BRANCH PCONTROL MAX_PEER PEERING SEEDS NETWORK SIGNED ENDHOST GATEWAY INFLUXDB DBMODE DBHOST DBPORT DBUSER DBPASS PNM KYC CRYPTO_BACK HTTPS_MODE ACCESS_TOKEN)
fi
if [ ! -v DGT_NOTA_PARAMS ]; then
DGT_NOTA_PARAMS=(PEER PNM CRYPTO_BACK USER_NOTARY BOT_TOKEN LADDR BON NREST SEAL_ADDR REST_API HTTPS_MODE ACCESS_TOKEN DGT_TOKEN)
fi
if [ ! -v DGT_GRAF_PARAMS ]; then
DGT_GRAF_PARAMS=(PEER API DBPORT DBUSER DBPASS DB_ADM_USER DB_ADM_PASS DBMODE)
fi
if [ ! -v DGT_DASH_PARAMS ]; then
DGT_DASH_PARAMS=(PEER CLUST NODE COMP API SIGNED PNM CRYPTO_BACK HTTPS_MODE ACCESS_TOKEN)
fi
if [ ! -v DGT_DEVEL_PARAMS ]; then
DGT_DEVEL_PARAMS=(PEER PNM CRYPTO_BACK HTTPS_MODE ACCESS_TOKEN DGT_TOKEN COMP_URL API)
fi

if [ ! -v PARAMS_HELP ]; then
declare -A PARAMS_HELP=(
    [PEER]="Dgt peer name: <name>"
    [CLUST]="Cluser name: 'c[1..9]'"
    [NODE]="Peer number in cluster: [1..]"
    [MAX_PEER]="Maximum peer connectivity: 70"
    [DAG_BRANCH]="Maximum DAG branch: 6"
    [API]="REST-API PORT"
    [COMP]="Component PORT"
    [NET]="Network PORT"
    [CONS]="Consensus PORT"
    [GENESIS]="Genesis mode: Y/N"
    [SINGLE]="Single peer mode: Y/N"
    [PCONTROL]="Peer list for control: <peer1>,<peer2>,"
    [PEERING]="Peering mode: static/dynamic"
    [SEEDS]="Seed list for static/dymanic:--seeds <seed1>,<seed2>, / --seeds <gateway>"
    [NETWORK]="Network name for this peer: net0"
    [ENDHOST]="External peer endpoint: tcp://<host>:<port>/"
    [GATEWAY]="The gateway as a link to a file hosted in the cloud or uri to DGT peer: ${DGT_GATEWAY} / tcp://<host>:<port>"
    [INFLUXDB]="User Influx DB: --opentsdb-url-off/--opentsdb-url <url>"
    [DBHOST]="Service name with Influx DB: stats-influxdb-dgt"
    [DBUSER]="Influx DB user: <user name>"
    [DBPASS]="Influx DB password: <password>"
    [DB_ADM_USER]="Influx DB admin: <admin name>"
    [DB_ADM_PASS]="Influx DB admin password: <password>"
    [DBMODE]="Influx DB mode: metrics"
    [DBPORT]="Influx DB port: 8086"
    [CRYPTO_BACK]="Cryptography type: openssl/bitcoin"
    [SIGNED]="Signed consensus mode: --signed_consensus/ "
    [HTTPS_MODE]="--http_ssl/ "
    [ACCESS_TOKEN]="Rest-api token: --access_token/ "
    [PNM]="DGT project name: dgt"
    [KYC]="KYC value: -kyc val/ "
    [BOT_TOKEN]="Telegram bot token: <token for telegram access>"
    [LADDR]="Notary leader uri: -la <uri> / "
    [SEAL_ADDR]="Notary seal keeper uri: vault-n1:8220"
    [DGT_TOKEN]="DGT REST-API token: <token>"
    [USER_NOTARY]="User notary name:--user-notary <user>"
    [NREST]="Notary rest-api mode: ON/OFF"
    [BON]="Teler bot mode: -bon/"
    [COMP_URL]="Url for component connect: tcp://validator-dgt-c1-1:4104"
)
fi


PEER_PARAMS=()
PEER_LIST=()
LNAME=

NPROTO="prototype"
delim=' '
CBLUE="\033[0m\033[36m"
CRED="\033[0m\033[31m"
CDEF="\033[0m"

# set type of peers- dgt node or dashboard
function setPeerType {
  if [[ $SNM == "dash"* ]]; then
            PEER_LIST=${DASH_LIST[@]}
            LNAME=DASH_LIST
            PEER_PARAMS=${DGT_DASH_PARAMS[@]}

  elif  [[ " ${CLUSTER_LIST[@]} " == *" $SNM "* ]] || [[ $SNM == "dgt"* ]] ; then
           PEER_LIST=${CLUSTER_LIST[@]}
           LNAME=CLUSTER_LIST
           PEER_PARAMS=${DGT_PARAMS[@]}
  elif [[ $SNM == "graf"* ]]; then
           PEER_LIST=${GRAF_LIST[@]}         
           LNAME=GRAF_LIST                   
           PEER_PARAMS=${DGT_GRAF_PARAMS[@]}
  elif [[ $SNM == "nota"* ]]; then                    
           PEER_LIST=${NOTARY_LIST[@]}         
           LNAME=NOTARY_LIST                   
           PEER_PARAMS=${DGT_NOTA_PARAMS[@]} 
  elif [[ $SNM == "dev"* ]]; then                    
           PEER_LIST=${DEVEL_LIST[@]}         
           LNAME=DEVEL_LIST                   
           PEER_PARAMS=${DGT_DEVEL_PARAMS[@]} 
 
 
  else 
        PEER_PARAMS=()
        echo -e $CRED "NO SUCH TYPE PEER." $CDEF
  fi

}
setPeerType
#echo "$LNAME='${PEER_LIST[@]}' params=(${PEER_PARAMS[@]}) "

function doNotaCompose {
   #echo "doDashCompose $@"
   if test -f $NOTA_FCOMP; then 
       eval PEER=\$PEER_${SNM^^}                                              
                                                           
       eval CLUST=\$CLUST_${SNM^^}                                                
       eval NODE=\$NODE_${SNM^^}                                                
       eval SIGNED=\$SIGNED_${SNM^^}
       eval PNM=\$PNM_${SNM^^}
       eval CRYPTO_BACK=\$CRYPTO_BACK_${SNM^^}
       eval HTTPS_MODE=\$HTTPS_MODE_${SNM^^}
       eval ACCESS_TOKEN=\$ACCESS_TOKEN_${SNM^^}
       eval API=\$API_${SNM^^}
       eval COMP=\$COMP_${SNM^^}

                                             
 
        #export COMPOSE_PROJECT_NAME=1 G=$GENESIS C=c1 N=1 API=8108 COMP=4104 NET=8101 CONS=5051;docker-compose -f docker/$FCOMPOSE $mode
        echo export COMPOSE_PROJECT_NAME=$SNM C=$CLUST N=$NODE API=$API COMP=$COMP  \
               SIGNED=$SIGNED  \
               PNM=$PNM CRYPTO_BACK=$CRYPTO_BACK KYC=$KYC HTTPS_MODE=$HTTPS_MODE; \
               $COMPOSE -f $NOTA_FCOMP $CMD $@;                           
       
   else                                                                              
       echo -e $CRED "Create and add $NOTA_FCOMP" $CDEF                      
   fi

}

function doGrafCompose {
   
   if test -f $GRAF_FCOMP; then 
       eval PEER=\$PEER_${SNM^^}                                              
                                                           
       eval API=\$API_${SNM^^}                                                
       eval DBPORT=\$DBPORT_${SNM^^}                                                
       eval DBUSER=\$DBUSER_${SNM^^}
       eval DBPASS=\$DBPASS_${SNM^^}
       eval DB_ADM_USER=\$DB_ADM_USER_${SNM^^}
       eval DB_ADM_PASS=\$DB_ADM_PASS_${SNM^^}
       eval DBMODE=\$DBMODE_${SNM^^}
       

        export COMPOSE_PROJECT_NAME=$SNM API=$API DBPORT=$DBPORT  \
               DBUSER=$DBUSER DBPASS=$DBPASS DB_ADM_USER=$DB_ADM_USER DB_ADM_PASS=$DB_ADM_PASS DBMODE=$DBMODE; \
               $COMPOSE -f $GRAF_FCOMP $CMD $@;                           
       
   else                                                                              
       echo -e $CRED "Create and add $GRAF_FCOMP" $CDEF                      
   fi

}

function doDashCompose {
   #echo "doDashCompose $@"
   if test -f $DASH_FCOMP; then 
       eval PEER=\$PEER_${SNM^^}                                              
                                                           
       eval CLUST=\$CLUST_${SNM^^}                                                
       eval NODE=\$NODE_${SNM^^}                                                
       eval SIGNED=\$SIGNED_${SNM^^}
       eval PNM=\$PNM_${SNM^^}
       eval CRYPTO_BACK=\$CRYPTO_BACK_${SNM^^}
       eval HTTPS_MODE=\$HTTPS_MODE_${SNM^^}
       eval ACCESS_TOKEN=\$ACCESS_TOKEN_${SNM^^}
       eval API=\$API_${SNM^^}
       eval COMP=\$COMP_${SNM^^}

                                             
 
        #export COMPOSE_PROJECT_NAME=1 G=$GENESIS C=c1 N=1 API=8108 COMP=4104 NET=8101 CONS=5051;docker-compose -f docker/$FCOMPOSE $mode
        export COMPOSE_PROJECT_NAME=$SNM C=$CLUST N=$NODE API=$API COMP=$COMP  \
               SIGNED=$SIGNED  \
               PNM=$PNM CRYPTO_BACK=$CRYPTO_BACK KYC=$KYC HTTPS_MODE=$HTTPS_MODE; \
               $COMPOSE -f $DASH_FCOMP $CMD $@;                           
       
   else                                                                              
       echo -e $CRED "Create and add $DASH_FCOMP" $CDEF                      
   fi

}
function doDevelCompose {
   
   if test -f $DEVEL_FCOMP; then 
       
       declare -A params=()  
       doPeerParams params   
                                             
        BIND_API="python-sdk-${params[PNM]}-${params[PEER]}:${params[API]}"
        #export COMPOSE_PROJECT_NAME=1 G=$GENESIS C=c1 N=1 API=8108 COMP=4104 NET=8101 CONS=5051;docker-compose -f docker/$FCOMPOSE $mode
        export COMPOSE_PROJECT_NAME=$SNM   \
               SIGNED=${params["SIGNED"]} PEER=${params["PEER"]} ACCESS_TOKEN=${params["ACCESS_TOKEN"]} BIND_API=$BIND_API \
               PNM=${params["PNM"]} CRYPTO_BACK=${params["CRYPTO_BACK"]}  HTTPS_MODE=${params["HTTPS_MODE"]} COMP_URL=${params["COMP_URL"]}; \
               $COMPOSE -f $DEVEL_FCOMP $CMD $@;                           
       
   else                                                                              
       echo -e $CRED "Create and add $DEVEL_FCOMP" $CDEF                      
   fi

}
function doPeerParams {
    local -n PARAMS=$1
    for var in ${PEER_PARAMS[@]}
    do
        vname="${var}_${SNM^^}"
        if [[ -z "${!vname}" ]];then
           if [ -v DEF_PARAMS[$var] ]; then
              PARAMS[$var]="${DEF_PARAMS[$var]}"
           else 
              PARAMS[$var]=""
           fi 
        else
           PARAMS[$var]=${!vname}
           
        fi
    done
}

function doPeerCompose {
   
   if test -f $FCOMPOSE; then 
       
        # set params and default 
        declare -A params=()
        doPeerParams params
        #declare -p params
        DGT_API="api-${params[PNM]}-${params[CLUST]}-${params[NODE]}:${params[API]}"
        if [[ ${params["HTTPS_MODE"]} == "--http_ssl" ]]; then
          DGT_API_URL="https://$DGT_API"  
        else
          DGT_API_URL="http://$DGT_API"
        fi
        #export COMPOSE_PROJECT_NAME=1 G=$GENESIS C=c1 N=1 API=8108 COMP=4104 NET=8101 CONS=5051;docker-compose -f docker/$FCOMPOSE $mode
        export COMPOSE_PROJECT_NAME=$SNM G=${params["GENESIS"]} C=${params["CLUST"]} N=${params["NODE"]} \
               API=${params["API"]} COMP=${params["COMP"]} NET=${params["NET"]} CONS=${params["CONS"]} \
               SINGLE=${params["SINGLE"]} SIGNED=${params["SIGNED"]}  PCONTROL=$PCONTROL MAX_PEER=${params["MAX_PEER"]} \
               ENDHOST=${params["ENDHOST"]} ENDPOINTS=${params["ENDPOINTS"]} SEEDS=${params["SEEDS"]} PEERS=${params["PEERS"]} \
               DAG_BRANCH=${params["DAG_BRANCH"]} PEERING=${params["PEERING"]} NETWORK=${params["NETWORK"]} DGT_API_URL=$DGT_API_URL \
               INFLUXDB=${params["INFLUXDB"]} DBHOST=${params["DBHOST"]} DBPORT=${params["DBPORT"]} DBUSER=${params["DBUSER"]} DBPASS=${params["DBPASS"]} DBMODE=${params["DBMODE"]} \
               PNM=${params["PNM"]} CRYPTO_BACK=${params["CRYPTO_BACK"]} KYC=${params["KYC"]} HTTPS_MODE=${params["HTTPS_MODE"]} ACCESS_TOKEN=${params["ACCESS_TOKEN"]}; \
               $COMPOSE -f $FCOMPOSE $CMD $@;                           
       
   else                                                                              
       echo -e $CRED "Create and add $FCOMPOSE"   $CDEF                      
   fi                                                                                

}
function doDgtCompose {
   eval PEER=\$PEER_${SNM^^}
   if [ -z ${PEER} ] ;then                                                            
      echo -e $CRED "UNDEFINED DGT PEER '$SNM'" $CDEF                              
      return                                                                                        
   fi

   echo -e $CBLUE "$CMD service $SNM"  $CDEF
   if [[ $LNAME == "DASH_LIST" ]]; then
        doDashCompose $@
        
   elif [[ $LNAME == "CLUSTER_LIST" ]] ; then
        doPeerCompose $@

   elif [[ $LNAME == "GRAF_LIST" ]] ; then
        doGrafCompose $@

   elif [[ $LNAME == "NOTARY_LIST" ]] ; then
        doNotaCompose $@
   elif [[ $LNAME == "DEVEL_LIST" ]] ; then
        doDevelCompose $@
   else 
        echo -e $CRED "UNDEFINED TYPE PEER" $CDEF
   fi
}
                                                                                                       

function doServiceCmd {
  
  if [ $SNM == 'all' ];then

    for SNM in $PEER_LIST  
    do
        #echo "... $SNM"
        doDgtCompose $@
    done
  else
  # single DGT service control
    
    doDgtCompose $@
  fi


}
function doImageLoad {
# load docker image 
  INAME="dgt-common-$DISTR"

    if test -f $INAME.tgz; then 

      read -e -p "Load docker image from ${INAME}.tgz (Y/N)?" -i "N" REPL
      if [[ $REPL == "Y" ]]; then

        echo "Import docker image $INAME.tgz"
        docker load -i $INAME.tgz && docker images | grep $INAME
      fi
    else
        echo "Can't find image $INAME.tgz"
    fi

}

function doImageSave {
# save docker image 
    INAME="dgt-common-$DISTR"
    read -e -p "Save docker image ${INAME} (Y/N)?" -i "N" REPL
    if [[ $REPL == "Y" ]]; then

      if test -f "$INAME.tgz"; then 
          echo "Image $INAME already saved"
          
          
      else
          echo "Save docker image $INAME"
          docker save -o $INAME.tgz $INAME 
      fi
    fi
}
function doListDgt {

    if [[ $1 == '-v' ]]; then           
                                        
      for NM in ${PEER_LIST[@]}              
      do     
          SNM=$NM                           
          doShowDgt $NM               
      done                              
    else                                
    # 
      echo -e $CBLUE "DGT PEER LIST:: ${PEER_LIST[@]}"  $CDEF                
    fi                                  



}
function doShowDgt { 
  NM=${1:-$SNM}

        eval PEER=\$PEER_${NM^^}
                          
        if [ -z ${PEER} ] ;then  
            echo -e $CRED "NO SUCH $NM DGT PEER " $CDEF
            return 
        fi
        echo -e $CBLUE "DGT PEER  $NM::" $CDEF
        declare -A params=()
        doPeerParams params

        for var in ${!params[@]}
        do
            echo -e $CBLUE "  $var=${params[$var]} " $CDEF

        done
   
                         
} 
function doCopyDgt { 
        eval PEER=\$PEER_${SNM^^}
                          
        if [ -z ${PEER} ] || [ -z ${1} ] ;then  
            echo -e $CRED "NO SUCH $SNM DGT PEER OR UNDEF TARGET PEER" $CDEF
            return 
        fi
        if [[ ${SNM} == ${1} ]] ;then
          echo -e $CRED "SET NEW PEER NAME NOT EQUAL $SNM" $CDEF
          return

        fi 
        eval NPEER=\$PEER_${1^^}
        if [ ! -z ${NPEER} ];then           
           echo -e $CRED "DGT PEER '$NPEER' ALREADY DEFINED" $CDEF
           return
        fi 

        echo -e $CBLUE "COPY ${SNM^^} DGT PEER INTO ${1^^}" $CDEF

        PEER_LIST+=($1)
        updatePeerList "$LNAME" "${PEER_LIST[@]}"

        echo "" >> $FILE_ENV                             
        echo "######### >> ${1^^} PEER ##########" >> $FILE_ENV  
        
        for var in ${PEER_PARAMS[@]}
        do
            p_val="${var}_${SNM^^}"
            
            if [[ $var == 'PEER' ]]; then
              echo "${var}_${1^^}=${1}"   >> $FILE_ENV
            else 
              if [[ ${!p_val} == *"$delim"* ]] ; then                       
                  echo "${var}_${1^^}=\"${!p_val}\""   >> $FILE_ENV    
              else  
                                                                  
                echo "${var}_${1^^}=${!p_val}"   >> $FILE_ENV        
              fi
            fi                                                       


        done
        echo "######### << ${1^^} DGT PEER ##########" >> $FILE_ENV
                         
}                        
function updateEnvParam {
 if grep -q "${1}=" "$FILE_ENV"; then
   # this param already defined try to update
   if [[ $2 != $3 ]]; then       
   echo -e  $CBLUE "update:: $1=$2 -> $3" $CDEF
   sed -i "s/$1=.*/$1=$3/"  $FILE_ENV
   fi
 else
  # new params
  after_par="PEER_${SNM^^}" 
  sed -i "/$after_par=.*/a $1=$3"  $FILE_ENV
                                  
 fi                                  

}
function updatePeerList {
nlist=$1;shift
lval="($@)"
if grep -q "${nlist}=" "$FILE_ENV"; then
 #echo "s/${nlist}=.*/${nlist}=${lval}/"
 sed -i "s/${nlist}=.*/${nlist}=${lval}/"  $FILE_ENV
else
 after_par="all dgt cluster"
 #echo "UNDEF LIST ${nlist}"
 sed -i "/$after_par.*/a ${nlist}=${lval}"  $FILE_ENV
fi


}
getParamHelp() {
  local name=$1
  local phelp=
    if [ -v PARAMS_HELP[$name] ]; then
       phelp="(${PARAMS_HELP[$name]})"
    fi

  echo $phelp



}
function printHelp {
 local -n HELP=$1
  
  desired_length=10 
  for key in "${!HELP[@]}"; do  
     padding_len=$((desired_length - ${#key}))
     padded_key="${key}$(printf '%*s' $padding_len)"                    
     echo -e $CBLUE "  $padded_key  ${HELP[$key]}" $CDEF  
  done
}


function doEditDgt {  
eval PEER=\$PEER_${SNM^^}
    
    if [ -z ${PEER} ];then           
      echo -e $CRED "DGT PEER '${SNM^^}' UNDEFINED" $CDEF
      return
    fi 
    

    #echo -e $CBLUE "EDIT ${SNM^^} DGT PEER " $CDEF
    if [[ $1 != "" ]]; then 
         PAR="$1_${SNM^^}"
         if [[ -v ${PAR} ]]; then
          #echo "UPDATE only $PAR = ${!PAR} "
          #echo -e $CBLUE "EDIT ${SNM^^} DGT PEER only param $1" $CDEF
          
          pvals=$(getParamHelp $1)
          echo -e $CBLUE "Set new value $pvals for ${SNM^^} DGT PEER" $CDEF
          read -e -p ">>> " -i "${!PAR}" NVAL   #-p "Set new value $pvals >>"
          # for uri change special for sed letter '/'
          NVAL=${NVAL////\\/}
          if [[ $NVAL == *"$delim"* ]]; then
          updateEnvParam $PAR "${!PAR}" "\"$NVAL\""
          else
          updateEnvParam $PAR "${!PAR}" "$NVAL"
          fi
     
         else
           echo -e $CRED "UNDEFINED PARAM '$1' USE (${PEER_PARAMS[@]})" $CDEF
           
         fi
         return
    fi
    


    echo -e $CBLUE "EDIT ${SNM^^} DGT PEER " $CDEF
    for var in ${PEER_PARAMS[@]}
    do
       p_val="${var}_${SNM^^}"
       pvals=$(getParamHelp $var)
       echo -e $CBLUE "Update $var value $pvals" $CDEF
       read -e -p ">>> " -i "${!p_val}" NVAL  # "Set new value $var::"
       
       if [[ $NVAL == *"$delim"* ]]; then
             updateEnvParam $p_val "${!p_val}" "\"$NVAL\""
       else
             updateEnvParam $p_val "${!p_val}" "$NVAL"
       fi
    done
                                                                                                                
}                                                                                                               

function doAddDgt {

eval PEER=\$PEER_${SNM^^}
    
    if [ ! -z ${PEER} ];then           
      echo -e $CRED "DGT PEER '$PEER' ALREADY DEFINED" $CDEF
      return
    fi 

    PEER_LIST+=($SNM)               
    updatePeerList $LNAME "${PEER_LIST[@]}"     

    
    echo "ADD ${SNM^^} DGT PEER"
    
    echo "" >> $FILE_ENV
    echo "######### >> ${SNM^^} PEER ##########" >> $FILE_ENV
    for var in ${PEER_PARAMS[@]}
    do
    p_val="${var}_${NPROTO^^}"
    
    
    read -e -p "Set value for $var::" -i "${!p_val}" NVAL
    echo -e $CBLUE "  $var=$NVAL " $CDEF
    if [[ $NVAL == *"$delim"* ]]; then
        echo "${var}_${SNM^^}=\"${NVAL}\""   >> $FILE_ENV
    else
        echo "${var}_${SNM^^}=${NVAL}"   >> $FILE_ENV
    fi
    done
    echo "######### << ${SNM^^} DGT PEER ##########" >> $FILE_ENV


}
function set_mode_dynamic {

  
  # PEERING=dynamic SEEDS=--seeds <gateway>
  eval PEERING=\$PEERING_${SNM^^}
  eval SEEDS=\$SEEDS_${SNM^^}
  eval CLUST=\$CLUST_${SNM^^}

  if [[ $PEERING == *"static"* ]]; then
      NVAL="dynamic"
      NVAL1="--seeds"
      NCL="dyn"
      updateEnvParam "CLUST_${SNM^^}" "$CLUST" "$NCL"
      echo "Set dynamic mode for peer $snm"   
  else
      NVAL="static"
      NVAL1=""
      echo "Set static mode for peer $snm"
  fi
  updateEnvParam "SEEDS_${SNM^^}" "$SEEDS" "$NVAL1"
  updateEnvParam "PEERING_${SNM^^}" "$PEERING" "$NVAL"

}

function set_mode_https {

  
  eval HTTPS_MODE=\$HTTPS_MODE_${SNM^^}
  
  if [[ $HTTPS_MODE == *"--http_ssl"* ]]; then
      NVAL=""
      echo "Set http mode for peer $snm"   
  else
      NVAL="--http_ssl"
      echo "Set https mode for peer $snm"
  fi
  updateEnvParam "HTTPS_MODE_${SNM^^}" "$HTTPS_MODE" "$NVAL"

}
function set_mode_access {

  
  eval ACCESS_TOKEN=\$ACCESS_TOKEN_${SNM^^}
  eval HTTPS_MODE=\$HTTPS_MODE_${SNM^^}
  if [[ $ACCESS_TOKEN == *"--access_token"* ]]; then
      NVAL=""
      NVAL1=""
      echo "Set free access mode for peer $snm"   
  else
      NVAL="--access_token"
      NVAL1="--http_ssl"
      echo "Set token access mode for peer $snm"
      
  fi
  updateEnvParam "HTTPS_MODE_${SNM^^}" "$HTTPS_MODE" "$NVAL1"
  updateEnvParam "ACCESS_TOKEN_${SNM^^}" "$ACCESS_TOKEN" "$NVAL"

}
function set_mode_signed {

  
  eval SIGNED=\$SIGNED_${SNM^^}
  
  if [[ $SIGNED == *"--signed_consensus"* ]]; then
      NVAL=""
      echo "Set unsigned consensus mode for peer $snm"   
  else
      NVAL="--signed_consensus"
      echo "Set signed consensus mode for peer $snm"
  fi
  updateEnvParam "SIGNED_${SNM^^}" "$SIGNED" "$NVAL"

}

function set_mode_metric {
 # ${INFLUXDB} http://${DBHOST}:8086 --opentsdb-db metrics
  eval INFLUXDB=\$INFLUXDB_${SNM^^}

  if [[ $INFLUXDB == *"--opentsdb-url-off"* ]]; then
      NVAL="--opentsdb-url"
      echo "Switch ON metrics for peer $snm"   
  else
      NVAL="--opentsdb-url-off"
      echo "Switch OFF metrics for peer $snm"
  fi
  updateEnvParam "INFLUXDB_${SNM^^}" "$INFLUXDB" "$NVAL"


}

function set_mode_genesis {

eval GENESIS=\$GENESIS_${SNM^^}
  
  if [[ $GENESIS == "N" ]]; then
      NVAL=Y
      echo "Set genesis mode for peer $snm"   
  else
      NVAL=N
      echo "Reset genesis mode for peer $snm"
  fi
  updateEnvParam "GENESIS_${SNM^^}" "$GENESIS" "$NVAL"


}

function doModeDgt {
  # 
  eval PEER=\$PEER_${SNM^^}
  if [ -z ${PEER} ];then           
    echo -e $CRED "'$SNM' PEER UNDEFINED" $CDEF
    return
  fi
  if [[ $1 != "" ]]; then
     if [[ "$(type -t set_mode_$1)" == "function" ]]; then
       "set_mode_$1"
       return
     else
       echo -e $CRED "Undefined mode '$1'." $CDEF
       
     fi
  else 
     echo -e $CRED "Define mode which you want to set for '$SNM'" $CDEF
     
  fi
  echo -e $CBLUE "Use mode from list:" $CDEF
  printHelp MODES_HELP

}
function doConfDgt {
  # 
  eval PEER=\$PEER_${SNM^^}
  if [ -z ${PEER} ];then           
    echo -e $CRED "'$SNM' PEER UNDEFINED" $CDEF
    return
  fi
  if [[ $1 != "" ]]; then
     if [ -v CONFS_SRC[$1] ]; then
        #echo "Conf ${CONFS_SRC[$1]}"
        if ! command -v jq &> /dev/null
        then
          echo -e $CRED "Please install util 'jq'" $CDEF
        else
          cat ${CONFS_SRC[$1]} | jq 
        fi
        return
      else
       echo -e $CRED "Undefined config type '$1'." $CDEF
       
     fi
  else 
     echo -e $CRED "Define mode which you want to set for '$SNM'" $CDEF
     
  fi
  echo -e $CBLUE "Use config type from list:" $CDEF
  printHelp CONFS_HELP

}




function doDelDgt {
  # sed '/the/d' dummy.txt
  eval PEER=\$PEER_${SNM^^}
  if [ -z ${PEER} ];then           
    echo -e $CRED "'$SNM' DGT PEER UNDEFINED" $CDEF
    return
  fi 
  read -e -p "Drop DGT PEER ${SNM^^} declaration (Y/N)?" -i "N" REPL
  if [[ $REPL == "Y" ]]; then
   echo -e $CBLUE "DROP ${SNM^^} DGT PEER "  $CDEF

   PEER_LIST=(${PEER_LIST[@]/$SNM})
   updatePeerList $LNAME "${PEER_LIST[@]}"

   cmd="/>> ${SNM^^}/,/<< ${SNM^^}/d"
   
   sed -i -e "$cmd" $FILE_ENV
   # for old version
   for var in ${PEER_PARAMS[@]}   
   do 
        cmd="/${var}_${SNM^^}=/d"
        sed -i -e "$cmd" $FILE_ENV
   done                               

  fi


}
function doDockerCmd() {
    local container_name=$1;shift
    local container_id=$(docker ps -q -f "name=${container_name}")

    if [ -n "$container_id" ]; then
      #echo "Контейнер $container_name запущен."
      docker exec -it ${container_name} $@
    else
      echo "Service '$container_name' is not ready."
    fi
}

function doShellDgt {
    eval PEER=\$PEER_${SNM^^}
    if [[ $LNAME == "DEVEL_LIST" ]] ; then
      container_name="python-sdk-dgt-${PEER}"
    else 
    eval CLUST=\$CLUST_${SNM^^}
    eval NODE=\$NODE_${SNM^^}
    if [ -z ${CLUST} ] || [ -z ${NODE} ];then   
      echo -e $CRED "UDEFINED PEER '$SNM' " $CDEF        
      return
    fi
    container_name="shell-dgt-${CLUST}-${NODE}"
    fi
    doDockerCmd $container_name "bash"

}
function doTokenDgt {
    
    eval CLUST=\$CLUST_${SNM^^}
    eval NODE=\$NODE_${SNM^^}
    if [ -z ${CLUST} ] || [ -z ${NODE} ];then   
      echo -e $CRED "UDEFINED PEER '$SNM' " $CDEF        
      return
    fi
    local container_name="shell-dgt-${CLUST}-${NODE}"
    doDockerCmd $container_name "dgt token get -u dgt:matagami -sc show -sc trans --client clientC $@" 

}
function doDecDgt {
    
    eval CLUST=\$CLUST_${SNM^^}
    eval NODE=\$NODE_${SNM^^}
    if [ -z ${CLUST} ] || [ -z ${NODE} ];then   
      echo -e $CRED "UDEFINED PEER '$SNM' " $CDEF        
      return
    fi
    local container_name="shell-dgt-${CLUST}-${NODE}"
    doDockerCmd $container_name dec $@

}
function doDgtDgt {
local container_name=""
    if [[ $LNAME == "DEVEL_LIST" ]] ; then
      eval PEER=\$PEER_${SNM^^}
      container_name="python-sdk-dgt-${PEER}"
    else
       eval CLUST=\$CLUST_${SNM^^}
       eval NODE=\$NODE_${SNM^^}
       if [ -z ${CLUST} ] || [ -z ${NODE} ];then   
         echo -e $CRED "UDEFINED PEER ($SNM)" $CDEF        
         return
       fi
       container_name="shell-dgt-${CLUST}-${NODE}"
    fi
    if [[ $1 != "" ]]; then
       
       doDockerCmd $container_name $@
    else 
       echo -e $CBLUE "usage:<dgt util name> [<args>]" $CDEF
    fi
    
}


case $CMD in
     up | down | start | stop | restart | build | ps)
          doDgtCompose  $@
          ;;
     load)
          doImageLoad  $@              
          ;;              
     save)                    
          doImageSave  $@      
          ;;  
     list)                           
          doListDgt $@                   
          ;;           
     show)                  
          doShowDgt  $@                  
          ;;    
     edit)                        
          doEditDgt  $@                        
          ;;            
     add)                    
          doAddDgt  $@                    
          ;; 
     copy)                     
          doCopyDgt  $@                 
          ;;                           
     del)                             
          doDelDgt  $@                 
          ;;
     mode)                             
          doModeDgt  $@                 
          ;;
     conf)                     
          doConfDgt  $@        
          ;;                   
     shell)
         doShellDgt $@
         ;;    
     token)
         doTokenDgt $@
         ;;               
     dec)                
         doDecDgt $@     
         ;;
     run)                
         doDgtDgt $@     
         ;;    
                
     *)
          desired_length=12
          echo -e $CBLUE "usage:<peer name> <subcommand> [<args>]" $CDEF
          echo -e $CBLUE "peer types: [dgt|dash|graf|dev]" $CDEF
          echo -e $CBLUE "subcommands: " $CDEF
          printHelp CMDS_HELP                                                 
          
          ;;
esac


