#export COMPOSE_PROJECT_NAME=1 C=c1 N=1 API=8008 COMP=4104 NET=8101 CONS=5051;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
#export COMPOSE_PROJECT_NAME=2 C=c1 N=2 API=8009 COMP=4106 NET=8102 CONS=5052;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
#export COMPOSE_PROJECT_NAME=3 C=c1 N=3 API=8010 COMP=4107 NET=8103 CONS=5053;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
#export COMPOSE_PROJECT_NAME=4 C=c1 N=4 API=8011 COMP=4108 NET=8104 CONS=5054;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml up
#export COMPOSE_PROJECT_NAME=5 C=c1 N=5 API=8012 COMP=4109 NET=8105 CONS=5055;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml up
#export COMPOSE_PROJECT_NAME=6 C=c1 N=6 API=8013 COMP=4110 NET=8106 CONS=5056;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml up
# cluster 2
#export COMPOSE_PROJECT_NAME=21 C=c2 N=1 API=8208 COMP=4204 NET=8201 CONS=5251;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
#export COMPOSE_PROJECT_NAME=22 C=c2 N=2 API=8209 COMP=4206 NET=8202 CONS=5252;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
#export COMPOSE_PROJECT_NAME=23 C=c2 N=3 API=8210 COMP=4207 NET=8203 CONS=5253;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
# cluster 3
#export COMPOSE_PROJECT_NAME=31 C=c3 N=1 API=8308 COMP=4304 NET=8301 CONS=5351;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
#export COMPOSE_PROJECT_NAME=32 C=c3 N=2 API=8309 COMP=4306 NET=8302 CONS=5352;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
#export COMPOSE_PROJECT_NAME=33 C=c3 N=3 API=8310 COMP=4307 NET=8303 CONS=5353;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
# cluster 4
#export COMPOSE_PROJECT_NAME=41 C=c4 N=1 API=8408 COMP=4404 NET=8401 CONS=5451;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
#export COMPOSE_PROJECT_NAME=42 C=c4 N=2 API=8409 COMP=4406 NET=8402 CONS=5452;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
#export COMPOSE_PROJECT_NAME=43 C=c4 N=3 API=8410 COMP=4407 NET=8403 CONS=5453;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
# cluster 5
#export COMPOSE_PROJECT_NAME=51 C=c5 N=1 API=8508 COMP=4504 NET=8501 CONS=5551;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
#export COMPOSE_PROJECT_NAME=52 C=c5 N=2 API=8509 COMP=4506 NET=8502 CONS=5552;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
#export COMPOSE_PROJECT_NAME=53 C=c5 N=3 API=8510 COMP=4507 NET=8503 CONS=5553;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
# cluster 6
#export COMPOSE_PROJECT_NAME=61 C=c6 N=1 API=8608 COMP=4604 NET=8601 CONS=5651;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
#export COMPOSE_PROJECT_NAME=62 C=c6 N=2 API=8609 COMP=4606 NET=8602 CONS=5652;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
#export COMPOSE_PROJECT_NAME=63 C=c6 N=3 API=8610 COMP=4607 NET=8603 CONS=5653;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml down
mode=stop
peers="1 2 3"
export PNM="dgt"

if [ -z $GATEWAY ]; then 
  echo STATIC MODE;export DCONFIG='dgt_val.conf';export PEERING='static'; 
  else 
  echo DYNAMIC MODE;export DCONFIG='dgt_dyn.conf';export PEERING='dynamic';export SEEDS="--seeds $GATEWAY"; 
fi

function downCluster1 {
  echo "downCluster3 $#"
  for node in $@;do
    echo "START $node"
    case $node in
        1)
          export COMPOSE_PROJECT_NAME=1 G=$GENESIS C=c1 N=1 API=8108 COMP=4104 NET=8101 CONS=5051;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;                                                        
        2)                                                        
          export COMPOSE_PROJECT_NAME=2 G=$GENESIS C=c1 N=2 API=8109 COMP=4106 NET=8102 CONS=5052;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;                                                        
        3)                                                        
          export COMPOSE_PROJECT_NAME=3 G=$GENESIS C=c1 N=3 API=8110 COMP=4107 NET=8103 CONS=5053;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;                                                        
        4)                                                        
          export COMPOSE_PROJECT_NAME=4 G=$GENESIS C=c1 N=4 API=8111 COMP=4108 NET=8104 CONS=5054;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;                                                        
        5)                                                        
          export COMPOSE_PROJECT_NAME=5 G=$GENESIS C=c1 N=5 API=8112 COMP=4109 NET=8105 CONS=5055;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;                                                        
        6)                                                        
          export COMPOSE_PROJECT_NAME=6 G=$GENESIS C=c1 N=6 API=8113 COMP=4110 NET=8106 CONS=5056;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        *)
          echo "Undefined peer into cluster."
        ;;
     esac
  done
}
function downCluster2 {
  echo "downCluster3 $#"
  for node in $@;do
    #echo "START $node"
    case $node in
        1)
          export COMPOSE_PROJECT_NAME=21 G=$GENESIS C=c2 N=1 API=8208 COMP=4204 NET=8201 CONS=5251;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        2)
          export COMPOSE_PROJECT_NAME=22 G=$GENESIS C=c2 N=2 API=8209 COMP=4206 NET=8202 CONS=5252;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        3)
          export COMPOSE_PROJECT_NAME=23 G=$GENESIS C=c2 N=3 API=8210 COMP=4207 NET=8203 CONS=5253;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        4)
          export COMPOSE_PROJECT_NAME=24 G=$GENESIS C=c2 N=4 API=8211 COMP=4208 NET=8204 CONS=5254;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        5)
          export COMPOSE_PROJECT_NAME=25 G=$GENESIS C=c2 N=5 API=8212 COMP=4209 NET=8205 CONS=5255;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        6)
          export COMPOSE_PROJECT_NAME=26 G=$GENESIS C=c2 N=6 API=8213 COMP=4210 NET=8206 CONS=5256;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        7)
          export COMPOSE_PROJECT_NAME=27 G=$GENESIS C=c2 N=7 API=8214 COMP=4211 NET=8207 CONS=5257;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        *)
          echo "Undefined peer into cluster."
        ;;
     esac
  done
}
function downCluster3 {
  echo "downCluster3 $#"
  for node in $@;do
    #echo "START $node"
    case $node in
        1)
          export COMPOSE_PROJECT_NAME=31 G=$GENESIS C=c3 N=1 API=8308 COMP=4304 NET=8301 CONS=5351;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;                                          
        2)                                          
          export COMPOSE_PROJECT_NAME=32 G=$GENESIS C=c3 N=2 API=8309 COMP=4306 NET=8302 CONS=5352;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;                                          
        3)                                          
          export COMPOSE_PROJECT_NAME=33 G=$GENESIS C=c3 N=3 API=8310 COMP=4307 NET=8303 CONS=5353;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        7)
          export COMPOSE_PROJECT_NAME=37 G=$GENESIS C=c3 N=7 API=8314 COMP=4311 NET=8307 CONS=5357;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        *)
          echo "Undefined peer into cluster."
        ;;
     esac
  done
}
function downCluster4 {
  echo "downCluster4 $#"
  for node in $@;do
    #echo "START $node"
    case $node in
        1)
          export COMPOSE_PROJECT_NAME=41 G=$GENESIS C=c4 N=1 API=8408 COMP=4404 NET=8401 CONS=5451;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;                                          
        2)                                          
          export COMPOSE_PROJECT_NAME=42 G=$GENESIS C=c4 N=2 API=8409 COMP=4406 NET=8402 CONS=5452;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;                                          
        3)                                          
          export COMPOSE_PROJECT_NAME=43 G=$GENESIS C=c4 N=3 API=8410 COMP=4407 NET=8403 CONS=5453;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        *)
          echo "Undefined peer into cluster."
        ;;
     esac
  done
}
function downCluster5 {
  echo "downCluster5 $#"
  for node in $@;do
    echo "START $node"
    case $node in
        1)
          export COMPOSE_PROJECT_NAME=51 G=$GENESIS C=c5 N=1 API=8508 COMP=4504 NET=8501 CONS=5551;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;                                          
        2)                                          
          export COMPOSE_PROJECT_NAME=52 G=$GENESIS C=c5 N=2 API=8509 COMP=4506 NET=8502 CONS=5552;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;                                          
        3)                                          
          export COMPOSE_PROJECT_NAME=53 G=$GENESIS C=c5 N=3 API=8510 COMP=4507 NET=8503 CONS=5553;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        *)
          echo "Undefined peer into cluster."
        ;;
     esac
  done
}
function downCluster6 {
  echo "downCluster6 $#"
  for node in $@;do
    echo "START $node"
    case $node in
        1)
          export COMPOSE_PROJECT_NAME=61 G=$GENESIS C=c6 N=1 API=8608 COMP=4604 NET=8601 CONS=5651;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;                                          
        2)                                          
          export COMPOSE_PROJECT_NAME=62 G=$GENESIS C=c6 N=2 API=8609 COMP=4606 NET=8602 CONS=5652;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;                                          
        3)                                          
          export COMPOSE_PROJECT_NAME=63 G=$GENESIS C=c6 N=3 API=8610 COMP=4607 NET=8603 CONS=5653;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        *)
          echo "Undefined peer into cluster."
        ;;
     esac
  done
}
function downClusterDyn {
  echo "downCluster Dynamic $#"
  for node in $@;do
    #echo "START $node"
    case $node in
        1)
          export COMPOSE_PROJECT_NAME=61 G=$GENESIS C=dyn N=1 API=8708 COMP=4704 NET=8701 CONS=5751;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        2)
          export COMPOSE_PROJECT_NAME=62 G=$GENESIS C=dyn N=2 API=8709 COMP=4706 NET=8702 CONS=5752;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        3)
          export COMPOSE_PROJECT_NAME=63 G=$GENESIS C=dyn N=3 API=8710 COMP=4707 NET=8703 CONS=5753;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        4)
          export COMPOSE_PROJECT_NAME=64 G=$GENESIS C=dyn N=4 API=8711 COMP=4708 NET=8704 CONS=5754;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        5)
          export COMPOSE_PROJECT_NAME=65 G=$GENESIS C=dyn N=5 API=8712 COMP=4709 NET=${ENDPORT:-8705} CONS=5755;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        6)
          export COMPOSE_PROJECT_NAME=66 G=$GENESIS C=dyn N=6 API=8713 COMP=4710 NET=${ENDPORT:-8706} CONS=5756;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        7)
          export COMPOSE_PROJECT_NAME=67 G=$GENESIS C=dyn N=7 API=8714 COMP=4711 NET=${ENDPORT:-8707} CONS=5757;docker-compose -f docker/docker-compose-netCN-dgt-val-pbft.yaml $mode
        ;;
        *)
          echo "Undefined peer into cluster."
        ;;
     esac
  done
}
cluster=$1
shift
case $cluster in
     1|genesis)
          echo "Stop cluster genesis"
          if (( $# > 0 ));then
            downCluster1 $@
          else  
            downCluster1 $peers 
          fi
          ;;
     2)
          echo "Stop cluster 2"
          if (( $# > 0 ));then
            downCluster2 $@
          else  
            downCluster2 $peers
          fi 
          ;;
     3)
          echo "Stop cluster 3"
          if (( $# > 0 ));then
            downCluster3 $@
          else  
            downCluster3 $peers
          fi
          ;; 
     4)
          echo "Stop cluster 4"
          if (( $# > 0 ));then
            downCluster4 $@
          else  
            downCluster4 $peers
          fi 
          ;; 
     5)
          echo "Stop cluster 5"
          if (( $# > 0 ));then
            downCluster5 $@
          else  
            downCluster5 $peers
          fi
          ;; 
     6)
          echo "Stop cluster 6"
          if (( $# > 0 ));then
            downCluster6 $@
          else  
            downCluster6 $peers 
          fi
          
          ;;
     dyn)
          echo "Stop dyamic cluster"
          if (( $# > 0 ));then
            downClusterDyn $@
          else  
            downClusterDyn $peers 
          fi
          
          ;;

     all)
          downCluster1 $peers
          downCluster2 $peers
          downCluster3 $peers
          downCluster4 $peers
          downCluster5 $peers
          downCluster6 $peers 
          ;;   
     *)
          echo "Enter cluster number."
          ;;
esac

