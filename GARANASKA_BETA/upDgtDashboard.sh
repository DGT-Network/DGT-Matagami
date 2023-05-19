# START DGT DASHBOARD
export CRYPTO_BACK="openssl"
export HTTPS_MODE=""
export PNM="dgt"
export ACCESS_TOKEN=""
while [ -n "$1" ]
do
case "$1" in
-SC) export SIGNED="--signed_consensus";echo "Signed consensus." ;;
-HTTPS) export HTTPS_MODE="--http_ssl";echo "Https mode." ;;
-ATOK) export ACCESS_TOKEN="--access_token";echo "Token mode." ;;
-CB) shift; export CRYPTO_BACK=$1 ;;
--) shift;break ;;
*) break ;;
esac
shift
done

docker-compose -f docker/docker-compose-dashboard-dgt-ci.yaml $@
