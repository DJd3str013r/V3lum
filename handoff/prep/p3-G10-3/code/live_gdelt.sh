#!/bin/bash
# Live GDELT DOC 2.0 checks for batch p3-G10-3 (benign public values only, >= 60 s apart, at most 4 calls).
# Usage: bash live_gdelt.sh <raw_dir>
RAW="$1"
BASE='https://api.gdeltproject.org/api/v2/doc/doc'
RISK='(fraude OR corrupcao OR preso OR investigado OR condenado OR denuncia OR golpe OR lavagem OR estelionato OR improbidade OR operacao OR desvio OR propina OR vazamento OR ransomware OR "ataque hacker" OR incidente OR "dados expostos" OR invasao)'
call() {
  local name="$1" query="$2" extra="$3"
  curl -sS --max-time 25 -G "$BASE" --data-urlencode "query=$query" --data "$extra" \
    -o "$RAW/$name.body" -D "$RAW/$name.headers" \
    -w "$name status=%{http_code} time=%{time_total} size=%{size_download} ct=%{content_type}\n" 2>&1
  date -u +%FT%TZ
}
wait_s() { sleep "$1"; }
wait_s 60
call gdelt_pos_a "\"banco do brasil\" $RISK sourcelang:portuguese" 'mode=artlist&format=json&maxrecords=50&timespan=3months&sort=datedesc'
wait_s 60
call gdelt_empty "\"zzqxv inexistente exemplo\" $RISK sourcelang:portuguese" 'mode=artlist&format=json&maxrecords=50&timespan=3months&sort=datedesc'
wait_s 60
call gdelt_short "ab sourcelang:portuguese" 'mode=artlist&format=json&maxrecords=5&timespan=3months'
if ! grep -q '"articles"' "$RAW/gdelt_pos_a.body" 2>/dev/null; then
  wait_s 90
  call gdelt_pos_b "\"banco do brasil\" $RISK sourcecountry:brazil" 'mode=artlist&format=json&maxrecords=50&timespan=3months&sort=datedesc'
fi
echo done
