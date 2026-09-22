#!/bin/sh
# Load the TEXT/BYTE fixture of the live test into a container made as in
# the README. Informix only takes TEXT and BYTE values through host
# variables, so the rows come from dbaccess LOAD, not from SQL literals.
set -e
ctr=${1:-libdrda-ifx}
db=${2:-drdatest}
docker cp "$(dirname "$0")/lob.unl" "$ctr":/tmp/lob.unl
docker exec "$ctr" bash -lc "cat > /tmp/lob.sql <<SQL
drop table if exists drda_lob;
create table drda_lob (id int, tx text, by byte, n int);
load from /tmp/lob.unl insert into drda_lob;
SQL
dbaccess $db /tmp/lob.sql"
