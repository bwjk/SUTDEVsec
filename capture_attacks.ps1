# capture_attacks.ps1
# Run EVSecSim attack profiles and save a pcap for each one.
#
# Usage:
#   .\capture_attacks.ps1                  # capture all profiles (~7 min)
#   .\capture_attacks.ps1 -Profile fdi     # capture one profile
#
# Output: captures\attack_<label>.pcap  -- open in Wireshark
# OCPP dissection: right-click port-9000 stream -> Decode As -> WebSocket

param(
    [string]$Profile = "all"
)

$CaptureDir = "captures"
New-Item -ItemType Directory -Force -Path $CaptureDir | Out-Null

function Invoke-Capture($prof, $container, $filter, $duration, $label) {
    $pcapOut = "$CaptureDir\attack_${label}.pcap"
    $tmpPcap = "/tmp/capture_${label}.pcap"

    Write-Host ""
    Write-Host "========================================================"
    Write-Host "  Profile   : $prof"
    Write-Host "  Capture in: $container"
    Write-Host "  Filter    : $filter"
    Write-Host "  Duration  : ${duration}s"
    Write-Host "  Output    : $pcapOut"
    Write-Host "========================================================"

    # Clean up leftovers from any previous run (--remove-orphans clears renamed services)
    docker compose --profile $prof down --remove-orphans 2>$null

    Write-Host "[$prof] Building and starting containers..."
    docker compose --profile $prof up -d --build
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[$prof] ERROR: docker compose up failed -- skipping"
        return
    }

    Write-Host "[$prof] Waiting 8s for containers to initialise..."
    Start-Sleep 8

    Write-Host "[$prof] Starting tcpdump inside '$container'..."
    docker exec -d $container sh -c "tcpdump -i any -w $tmpPcap '$filter' 2>/tmp/tcpdump_${label}.log"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[$prof] ERROR: tcpdump failed -- is NET_ADMIN set? Rebuild with --build."
        docker compose --profile $prof down
        return
    }

    Write-Host "[$prof] Capturing for ${duration}s ..."
    Start-Sleep $duration

    Write-Host "[$prof] Stopping tcpdump (SIGINT flushes the file)..."
    docker exec $container pkill -SIGINT tcpdump
    Start-Sleep 3

    Write-Host "[$prof] Copying pcap out of container..."
    docker cp "${container}:${tmpPcap}" $pcapOut

    if (Test-Path $pcapOut) {
        $bytes = (Get-Item $pcapOut).Length
        Write-Host "[$prof] Saved: $pcapOut  ($bytes bytes)"
    } else {
        Write-Host "[$prof] WARNING: pcap missing -- check tcpdump log inside container"
    }

    Write-Host "[$prof] Tearing down..."
    docker compose --profile $prof down --remove-orphans
    Start-Sleep 5
}

# Profile -> container, filter, duration(s), output label
switch ($Profile) {
    "normal"   { Invoke-Capture "normal"   "csms"         "port 9000"                  30 "normal_baseline" }
    "saiflow"  { Invoke-Capture "saiflow"  "csms"         "port 9000"                  75 "saiflow_dos" }
    "fdi"      { Invoke-Capture "fdi"      "csms"         "port 9000"                  60 "fdi" }
    "mitm"     { Invoke-Capture "mitm"     "csms"         "port 9000 or port 9001"     45 "mitm_internal" }
    "mitm-ext" { Invoke-Capture "mitm-ext" "csms"         "port 9000 or port 9002"     45 "mitm_external" }
    "load"     { Invoke-Capture "load"     "csms"         "port 9000"                  60 "load_altering" }
    "firmware"       { Invoke-Capture "firmware"       "atk-firmware"       "port 9000 or port 8080"     45 "firmware_update" }
    "duration-spoof" { Invoke-Capture "duration-spoof" "atk-duration-spoof" "port 9000 or port 9003"     80 "duration_spoof" }
    "all" {
        Write-Host "Capturing all attack profiles in sequence (~9 min total)..."
        Invoke-Capture "normal"         "csms"               "port 9000"                  30 "normal_baseline"
        Invoke-Capture "saiflow"        "csms"               "port 9000"                  75 "saiflow_dos"
        Invoke-Capture "fdi"            "csms"               "port 9000"                  60 "fdi"
        Invoke-Capture "mitm"           "csms"               "port 9000 or port 9001"     45 "mitm_internal"
        Invoke-Capture "mitm-ext"       "csms"               "port 9000 or port 9002"     45 "mitm_external"
        Invoke-Capture "load"           "csms"               "port 9000"                  60 "load_altering"
        Invoke-Capture "firmware"       "atk-firmware"       "port 9000 or port 8080"     45 "firmware_update"
        Invoke-Capture "duration-spoof" "atk-duration-spoof" "port 9000 or port 9003"     80 "duration_spoof"
    }
    default {
        Write-Host "Unknown profile: $Profile"
        Write-Host "Valid values: all, normal, saiflow, fdi, mitm, mitm-ext, load, firmware, duration-spoof"
        exit 1
    }
}

Write-Host ""
Write-Host "========================================================"
Write-Host "  Done. Pcap files saved to .\$CaptureDir\"
$files = Get-ChildItem $CaptureDir -Filter "*.pcap" -ErrorAction SilentlyContinue
if ($files) {
    foreach ($f in $files) {
        Write-Host "  $($f.Name)  ($($f.Length) bytes)"
    }
}
Write-Host ""
Write-Host "  Wireshark tips:"
Write-Host "  - Right-click any TCP stream on port 9000 -> Decode As -> WebSocket"
Write-Host "  - Filter: websocket  (OCPP JSON visible in packet details)"
Write-Host "  - For firmware: also filter  http  (port 8080 payload delivery)"
Write-Host "========================================================"
