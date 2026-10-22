#!/bin/bash
# Moves Radarr/Sonarr to a single /data mount (hardlinks instead of copies).
# Run on the Proxmox host: curl -fsSL <raw url> | bash
# CT and container names can be overridden: CT=200 bash arrfix.sh
set -e
CT=${CT:-200}
inner=$(mktemp)
cat > "$inner" <<'EOF'
#!/bin/sh
set -e
apk add -q curl jq >/dev/null
fix() {
  U=$1; K=$2; APP=$3
  api() { curl -fsS --retry 20 --retry-all-errors --retry-delay 3 -H "X-Api-Key: $K" -H "Content-Type: application/json" "$@"; }
  echo "== $APP"
  api "$U/api/v3/system/status" >/dev/null
  for h in $(api "$U/api/v3/downloadclient" | jq -r '.[].fields[] | select(.name=="host") | .value' | sort -u); do
    if api "$U/api/v3/remotepathmapping" | jq -e --arg h "$h" 'any(.[]; .host==$h and .remotePath=="/downloads/")' >/dev/null; then
      echo "mapping for $h already there"
    else
      api -X POST "$U/api/v3/remotepathmapping" -d "$(jq -n --arg h "$h" '{host:$h,remotePath:"/downloads/",localPath:"/data/downloads/"}')" >/dev/null
      echo "added mapping $h /downloads/ -> /data/downloads/"
    fi
  done
  api "$U/api/v3/config/mediamanagement" | jq '.copyUsingHardlinks=true' > /tmp/mm.json
  api -X PUT "$U/api/v3/config/mediamanagement/$(jq .id /tmp/mm.json)" -d @/tmp/mm.json >/dev/null
  echo "hardlinks on"
  shift 3
  for pair in "$@"; do
    old=${pair%%=*}; new=${pair#*=}
    if ! api "$U/api/v3/rootfolder" | jq -e --arg p "$new" 'any(.[]; (.path|rtrimstr("/"))==$p)' >/dev/null; then
      api -X POST "$U/api/v3/rootfolder" -d "$(jq -n --arg p "$new" '{path:$p}')" >/dev/null
      echo "added root $new"
    fi
    if [ "$APP" = radarr ]; then
      ids=$(api "$U/api/v3/movie" | jq -c --arg o "$old/" '[.[] | select(.path|startswith($o)) | .id]')
      [ "$ids" = "[]" ] || api -X PUT "$U/api/v3/movie/editor" -d "{\"movieIds\":$ids,\"rootFolderPath\":\"$new\",\"moveFiles\":false}" >/dev/null
    else
      ids=$(api "$U/api/v3/series" | jq -c --arg o "$old/" '[.[] | select(.path|startswith($o)) | .id]')
      [ "$ids" = "[]" ] || api -X PUT "$U/api/v3/series/editor" -d "{\"seriesIds\":$ids,\"rootFolderPath\":\"$new\",\"moveFiles\":false}" >/dev/null
    fi
    echo "moved $(echo "$ids" | jq length) entries $old -> $new"
    for id in $(api "$U/api/v3/rootfolder" | jq -r --arg o "$old" '.[] | select((.path|rtrimstr("/"))==$o) | .id'); do
      api -X DELETE "$U/api/v3/rootfolder/$id" >/dev/null
      echo "removed old root $old"
    done
  done
}
fix "http://radarr:7878$RB" "$RK" radarr /movies=/data/movies
fix "http://sonarr:8989$SB" "$SK" sonarr /tv=/data/tv /anime=/data/anime
echo DONE
EOF
pct push "$CT" "$inner" /root/arrfix-inner.sh
rm -f "$inner"
pct exec "$CT" -- sh -c '
k() { sed -n "s:.*<$2>\(.*\)</$2>.*:\1:p" /opt/$1/config.xml; }
for c in radarr sonarr; do
  docker exec $c test -d /data/downloads || { echo "$c has no /data/downloads: redeploy the arrs stack with /drivepool:/data first"; exit 1; }
done
docker run --rm --network proxy_net -v /root/arrfix-inner.sh:/fix.sh \
  -e RK="$(k radarr ApiKey)" -e SK="$(k sonarr ApiKey)" \
  -e RB="$(k radarr UrlBase)" -e SB="$(k sonarr UrlBase)" \
  alpine:3.20 sh /fix.sh
'
