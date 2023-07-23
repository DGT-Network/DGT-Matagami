#!/bin/bash
# DGT SERVICE CONTROL
#
source ./.env.dgt
FILE_ENV=./.env.dgt
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
#FCOMPOSE="docker-compose-netCN-dgt-dec-ci.yaml"
#DGT_PARAM_LIST=${DGT_PARAMS[@]} #(PEER CLUST NODE GENESIS SINGLE PCONTROL PEERING NETWORK METRIC SIGNED INFLUXDB DBHOST DBUSER DBPASS PNM KYC CRYPTO_BACK HTTPS_MODE ACCESS_TOKEN)
declare -A MODES_HELP=(
 [dynamic]="Set/reset peer in dynamic mode"
 [access]="Set/reset token access mode"
 [https]="Set/reset https mode"
 [genesis]="Set/reset genesis mode for peer"
 [signed]="Set/reset signed consensus mode for peer"

)
declare -A CMDS_HELP=(
 [build]="Build or rebuild services: ./dgt_control.sh c1_1 build validator-dgt"
 [up]="Create and start DGT containers: ./dgt_control.sh c1_1 up [-d]"
 [down]="Stop and remove DGT containers, networks, images, and volumes: ./dgt_control.sh c1_1 down"
 [start]="Start DGT services: ./dgt_control.sh c1_1 start"
 [stop]="Stop DGT services: ./dgt_control.sh c1_1 stop"
 [restart]="Restart DGT services: ./dgt_control.sh c1_1 restart"
 [list]="print DGT peer's params: ./dgt_control.sh dgt list [-v]"
 [show]="DGT peer params: ./dgt_control.sh c1_2 show"
 [edit]="edit DGT peer params: ./dgt_control.sh c1_1 edit [<param name>]"
 [add]="Add new DGT peer: ./dgt_control.sh c4_1 add"
 [del]="Drop peer declaration: ./dgt_control.sh c4_1 del"
 [copy]="make peer copy: ./dgt_control.sh c1_1 copy <new peer name>"
 [mode]="change peer mode: ./dgt_control.sh c1_1 <mode name>"
 [shell]="Enter into peer shell: ./dgt_control.sh c1_1 shell"
 [token]="Generate access token: ./dgt_control.sh c1_1 token"
 [dec]="run dec commands: ./dgt_control.sh c1_1 dec list"

)

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

function doPeerCompose {
   
   if test -f $FCOMPOSE; then 
       eval PEER=\$PEER_${SNM^^}                                              
       eval CLUST=\$CLUST_${SNM^^}                                                
       eval NODE=\$NODE_${SNM^^}                                                
       eval GENESIS=\$GENESIS_${SNM^^}                                           
       eval SINGLE=\$SINGLE_${SNM^^}
       eval PCONTROL=\$PCONTROL_${SNM^^} 
       eval PEERING=\$PEERING_${SNM^^} 
       eval NETWORK=\$NETWORK_${SNM^^}                                           
       eval METRIC=\$METRIC_${SNM^^}
       eval SIGNED=\$SIGNED_${SNM^^}
       eval INFLUXDB=\$INFLUXDB_${SNM^^}                                         
       eval DBHOST=\$DBHOST_${SNM^^}                                           
       eval DBUSER=\$DBUSER_${SNM^^}
       eval DBPASS=\$DBPASS_${SNM^^}
       eval PNM=\$PNM_${SNM^^}
       eval CRYPTO_BACK=\$CRYPTO_BACK_${SNM^^}
       eval KYC=\$KYC_${SNM^^}
       eval HTTPS_MODE=\$HTTPS_MODE_${SNM^^}
       eval ACCESS_TOKEN=\$ACCESS_TOKEN_${SNM^^}
       eval API=\$API_${SNM^^}
       eval COMP=\$COMP_${SNM^^}
       eval NET=\$NET_${SNM^^}
       eval CONS=\$CONS_${SNM^^} 
                                             
 
        #export COMPOSE_PROJECT_NAME=1 G=$GENESIS C=c1 N=1 API=8108 COMP=4104 NET=8101 CONS=5051;docker-compose -f docker/$FCOMPOSE $mode
        export COMPOSE_PROJECT_NAME=$SNM G=$GENESIS C=$CLUST N=$NODE API=$API COMP=$COMP NET=$NET CONS=$CONS \
               GENESIS=$GENESIS SINGLE=$SINGLE PCONTROL=$PCONTROL PEERING=$PEERING NETWORK=$NETWORK \
               METRIC=$METRIC SIGNED=$SIGNED INFLUXDB=$INFLUXDB DBHOST=$DBHOST DBUSER=$DBUSER DBPASS=$DBPASS \
               PNM=$PNM CRYPTO_BACK=$CRYPTO_BACK KYC=$KYC HTTPS_MODE=$HTTPS_MODE ACCESS_TOKEN=$ACCESS_TOKEN; \
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
    if test -f plc-$DISTR.tgz; then 
        echo "Import docker image plc-$DISTR.tgz"
        docker load -i  plc-$DISTR.tgz && docker images | grep plc-$DISTR
    else
        echo "Can't find image plc-$DISTR.tgz"
    fi
}

function doImageSave {
# save docker image 
    if test -f plc-$DISTR.tgz; then 
        echo "Image plc-$DISTR already saved"
        
        
    else
        echo "Save docker image plc-$DISTR"
        docker save -o plc-$DISTR.tgz  plc-$DISTR 
    fi
}
function doListDgt {

    if [[ $1 == '-v' ]]; then           
                                        
      for NM in ${PEER_LIST[@]}              
      do                                
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
        for var in ${PEER_PARAMS[@]}
        do
            p_val="${var}_${NM^^}"
            
            echo -e $CBLUE "  $var=${!p_val} " $CDEF

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

 if [[ $2 != $3 ]]; then       
 echo -e  $CBLUE "update:: $1=$2 -> $3" $CDEF
 sed -i "s/$1=.*/$1=$3/"  $FILE_ENV
 fi                                   

}
function updatePeerList {
nlist=$1;shift
lval="($@)"
 #echo "s/${nlist}=.*/${nlist}=${lval}/"
 sed -i "s/${nlist}=.*/${nlist}=${lval}/"  $FILE_ENV


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

function doShellDgt {
    
    eval CLUST=\$CLUST_${SNM^^}
    eval NODE=\$NODE_${SNM^^}
    if [ -z ${CLUST} ] || [ -z ${NODE} ];then   
      echo -e $CRED "UDEFINED PEER '$SNM' " $CDEF        
      return
    fi

    docker exec -it shell-dgt-${CLUST}-${NODE} bash

}
function doTokenDgt {
    
    eval CLUST=\$CLUST_${SNM^^}
    eval NODE=\$NODE_${SNM^^}
    if [ -z ${CLUST} ] || [ -z ${NODE} ];then   
      echo -e $CRED "UDEFINED PEER '$SNM' " $CDEF        
      return
    fi

    docker exec -it shell-dgt-${CLUST}-${NODE}  dgt token get -u dgt:matagami -sc show -sc trans --client clientC

}
function doDecDgt {
    
    eval CLUST=\$CLUST_${SNM^^}
    eval NODE=\$NODE_${SNM^^}
    if [ -z ${CLUST} ] || [ -z ${NODE} ];then   
      echo -e $CRED "UDEFINED PEER '$SNM' " $CDEF        
      return
    fi

    docker exec -it shell-dgt-${CLUST}-${NODE} dec $@

}



case $CMD in
     up)
          doDgtCompose  $@
          ;;
     down)
          doDgtCompose  $@
          ;;
     start)                  
         doDgtCompose  $@  
         ;;                
     stop)
          doDgtCompose  $@
          ;;
     restart)                      
          doDgtCompose  $@      
          ;;      
     build)                       
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

     shell)
         doShellDgt $@
         ;;    
     token)
         doTokenDgt $@
         ;;               
     dec)                
         doDecDgt $@     
         ;;                
     *)
          desired_length=12
          echo -e $CBLUE "usage:<peer name> <subcommand> [<args>]" $CDEF
          echo -e $CBLUE "subcommands: " $CDEF
          printHelp CMDS_HELP                                                 
          
          ;;
esac


