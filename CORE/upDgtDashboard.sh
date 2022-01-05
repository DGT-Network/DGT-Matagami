# START DGT DASHBOARD
export CRYPTO_BACK="bitcoin"
while [ -n "$1" ]
do
case "$1" in
-SC) export SIGNED="--signed_consensus";echo "Signed consensus." ;;
-CB) shift; export CRYPTO_BACK=$1 ;;
--) shift;break ;;
*) break ;;
esac
shift
done

docker-compose -f docker/docker-compose-dashboard-dgt.yaml up #-d
