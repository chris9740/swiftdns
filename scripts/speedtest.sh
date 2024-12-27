json_output="$(speedtest --json)"

download_bps=$(echo $json_output | jq -r '.download')
upload_bps=$(echo $json_output | jq -r '.upload')
ping_ms=$(echo $json_output | jq -r '.ping')
server_name=$(echo $json_output | jq -r '.server.name')
server_country=$(echo $json_output | jq -r '.server.country')
server_sponsor=$(echo $json_output | jq -r '.server.sponsor')
server_host=$(echo $json_output | jq -r '.server.host')

bps_to_mbps() {
    bps=$1
    echo "scale=2; $bps / 1000000" | bc
}

echo "Download: $(bps_to_mbps $download_bps) Mbps"
echo "Upload: $(bps_to_mbps $upload_bps) Mbps"
echo "Ping: $ping_ms ms"
echo "Server: $server_name ($server_country) - $server_sponsor"
echo "Host: $server_host"
