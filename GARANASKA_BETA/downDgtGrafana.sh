# STOP DGT GRAFANA
export DBUSER="lrdata"              
export DBPASS="pwlrdata" 
export DBMODE=metrics
export DB_ADM_USER="admin"   
export DB_ADM_PASS="pwadmin" 
export DBLOG=debug
export API=3000
export DBPORT=8086
docker-compose -f docker/docker-compose-grafana-dgt.yml down
