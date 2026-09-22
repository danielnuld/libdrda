#!/bin/sh
# Start an Informix container with a drsocssl (DRDA over TLS) listener on
# host port 29090 and a self-signed certificate for "localhost", and copy
# its certificate to ./ifx-ca.pem for DRDA_TEST_CA_FILE.
set -e
ctr=${1:-libdrda-ifx-tls}
docker run -d --name "$ctr" -h localhost -e LICENSE=accept \
  -p 29089:9089 -p 29090:9090 icr.io/informix/informix-developer-database
# On its first start the engine builds the system databases after going
# on-line; restarting it before they are done leaves sysmaster half built.
until docker exec "$ctr" bash -lc 'grep -q "sysadmin. database built successfully"     $(onstat -c 2>/dev/null | awk "/^MSGPATH/{print \$2}")' 2>/dev/null; do sleep 5; done
docker exec -u informix "$ctr" bash -lc '
set -e
mkdir -p $INFORMIXDIR/ssl && cd $INFORMIXDIR/ssl
gsk8capicmd_64 -keydb -create -db informix.kdb -pw in4mix -type cms -stash
gsk8capicmd_64 -cert -create -db informix.kdb -stashed -label ifxcert \
  -dn "CN=localhost" -san_dnsname localhost -size 2048 -expire 365 -default_cert yes
gsk8capicmd_64 -cert -extract -db informix.kdb -stashed -label ifxcert \
  -target /tmp/ifx-ca.pem -format ascii
chmod 600 informix.kdb informix.sth
cfg=$INFORMIXDIR/etc/$ONCONFIG
sed -i "s/^SSL_KEYSTORE_LABEL.*/SSL_KEYSTORE_LABEL ifxcert/; s/^DBSERVERALIASES.*/DBSERVERALIASES informix_dr,informix_drs/" $cfg
echo "NETTYPE drsocssl,1,50,NET" >> $cfg
echo "informix_drs drsocssl *localhost 9090" >> $INFORMIXSQLHOSTS
# Restart the engine, not the container: the container rewrites sqlhosts
# when it starts. onmode -ky can leave shared memory behind; free it.
onmode -ky || true
sleep 5
for id in $(ipcs -m | awk "\$3==\"informix\" {print \$2}"); do ipcrm -m $id; done
oninit -v >/tmp/oninit.log 2>&1'
until docker exec "$ctr" bash -lc 'onstat -g ntt' 2>/dev/null | grep -q "|9090|"; do sleep 3; done
docker cp "$ctr":/tmp/ifx-ca.pem ./ifx-ca.pem
echo "TLS listener on localhost:29090, CA in ./ifx-ca.pem"
