# capture_attacks.ps1
# Run EVSecSim attack profiles and save a pcap for each one.
#
# Usage:
#   .\capture_attacks.ps1              # run and capture all profiles
#   .\capture_attacks.ps1 -Profile fdi # run and capture one profile
#
# Output: captures/attack_<label>.pcap  — open in Wireshark
# OCPP dissection in Wireshark: Analyze > Decode As > WebSocket Port 9000 -> OCPP

param(
    [ValidateSet("all","normal","saiflow","fdi","mitm","mitm-ext","load","firmware")]
    [string]$Profile = "all"
)

$CaptureDir = "captures"
New-Item -ItemType Directory -Force -Path $CaptureDir | Out-Null

# Each entry: which profile to run, which container to capture in (the traffic hub),
# the tcpdump BPF filter, how long to capture (seconds), and the output filename label.
$Attacks = @(
    [ordered]@{
        Profile   = "normal"
        Container = "csms"
        Filter    = "port 9000"
        Duration  = 30
        Label     = "normal_baseline"
    },
    [ordered]@{
        Profile   = "saiflow"
        Container = "csms"
        Filter    = "port 9000"
        Duration  = 75
        Label     = "saiflow_dos"
    },
    [ordered]@{
        Profile   = "fdi"
        Container = "csms"
        Filter    = "port 9000"
        Duration  = 60
        Label     = "fdi"
    },
    [ordered]@{
        Profile   = "mitm"
        Container = "csms"
        Filter    = "port 9000 or port 9001"
        Duration  = 45
        Label     = "mitm_internal"
    },
    [ordered]@{
        Profile   = "mitm-ext"
        Container = "csms"
        Filter    = "port 9000 or port 9002"
        Duration  = 45
        Label     = "mitm_external"
    },
    [ordered]@{
        Profile   = "load"
        Container = "csms"
        Filter    = "port 9000"
        Duration  = 60
        Label     = "load_altering"
    },
    [ordered]@{
        Profile   = "firmware"
        Container = "atk-firmware"
        Filter    = "port 9000 or port 8080"
        Duration  = 45
        Label     = "firmware_update"
    }
)

function Invoke-Capture {
    param([hashtable]$Attack)

    $prof      = $Attack.Profile
    $container = $Attack.Container
    $filter    = $Attack.Filter
    $duration  = $Attack.Duration
    $label     = $Attack.Label
    $pcapOut   = "$CaptureDir/attack_${label}.pcap"
    $tmpPcap   = "/tmp/capture_${label}.pcap"

    Write-Host ""
    Write-Host "========================================================"
    Write-Host "  Profile   : $prof"
    Write-Host "  Capture in: $container"
    Write-Host "  Filter    : $filter"
    Write-Host "  Duration  : ${duration}s"
    Write-Host "  Output    : $pcapOut"
    Write-Host "========================================================"

    # Clean up any leftover containers from a previous run
    docker compose --profile $prof down 2>$null

    Write-Host "[$prof] Building and starting containers..."
    docker compose --profile $prof up -d --build
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[$prof] ERROR: docker compose up failed — skipping"
        return
    }

    Write-Host "[$prof] Waiting 8s for containers to initialise..."
    Start-Sleep 8

    Write-Host "[$prof] Starting tcpdump in '$container'..."
    docker exec -d $container sh -c "tcpdump -i any -w $tmpPcap '$filter' 2>/tmp/tcpdump_${label}.log"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[$prof] ERROR: could not start tcpdump — is NET_ADMIN set and tcpdump installed?"
        docker compose --profile $prof down
        return
    }

    Write-Host "[$prof] Capturing for ${duration}s ..."
    Start-Sleep $duration

    Write-Host "[$prof] Stopping tcpdump (SIGINT flushes the file)..."
    docker exec $container pkill -SIGINT tcpdump
    Start-Sleep 3   # let tcpdump finish writing

    Write-Host "[$prof] Copying pcap out of container..."
    docker cp "${container}:${tmpPcap}" $pcapOut

    if (Test-Path $pcapOut) {
        $bytes = (Get-Item $pcapOut).Length
        Write-Host "[$prof] Saved: $pcapOut  ($bytes bytes)"
    } else {
        Write-Host "[$prof] WARNING: pcap not found — check /tmp/tcpdump_${label}.log inside container"
    }

    Write-Host "[$prof] Tearing down..."
    docker compose --profile $prof down
    Start-Sleep 2
}

# ── Main ─────────────────────────────────────────────────────────────────────

if ($Profile -eq "all") {
    Write-Host "Capturing all attack profiles in sequence."
    Write-Host "Total estimated time: ~7 minutes"
    foreach ($attack in $Attacks) {
        Invoke-Capture $attack
    }
} else {
    $attack = $Attacks | Where-Object { $_.Profile -eq $Profile }
    if ($null -eq $attack) {
        Write-Host "Unknown profile: $Profile"
        exit 1
    }
    Invoke-Capture $attack
}

Write-Host ""
Write-Host "========================================================"
Write-Host "  Done. Pcap files in ./$CaptureDir/"
Get-ChildItem $CaptureDir -Filter "*.pcap" | ForEach-Object {
    Write-Host "  $($_.Name)  ($($_.Length) bytes)"
}
Write-Host ""
Write-Host "  Wireshark tips:"
Write-Host "  - Decode As: right-click a TCP stream on port 9000/9001/9002"
Write-Host "    -> Decode As -> WebSocket"
Write-Host "  - OCPP frames appear as JSON inside WebSocket payloads"
Write-Host "  - Filter: websocket  (shows only WS frames)"
Write-Host "========================================================"
