# demo.ps1
# Runs the whole system one time: a server, an owner (alice), a team member (bob)
# and someone that is not in the team (carol).
#
# Run this from the secure_share folder, with the environment active:
#     .\demo.ps1
#
# The demo uses its own temporary folders, so the real keys and data are not touched.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$dataset = "..\make_dataset\outputs\synthetic\npm_versions_clean.csv"
if (-not (Test-Path $dataset)) { throw "No dataset yet. Run: python ..\make_dataset\main.py" }

$temp = Join-Path $env:TEMP ("secure_share_demo_" + (Get-Random))
$env:SECURE_SHARE_HOME = "$temp\clients"
$env:SECURE_SHARE_SERVER_DIR = "$temp\server"
$port = 8010
$url = "http://127.0.0.1:$port"
$serverKey = "$temp\server\server_public.pem"

$server = $null
try {
    # STEP 1: First, the server generates its RSA keys (public and private) and starts.
    python server.py keygen
    $server = Start-Process python -ArgumentList "server.py", "run", $port -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 2

    # STEP 1 and 2: Then, each client generates its keys and registers. The client creates
    # a signature over its own public key and sends over the public key with the signature,
    # and the server verifies it and stores the public key on file.
    foreach ($name in "alice", "bob", "carol") {
        python client.py $name keygen
        python client.py $name register $url $serverKey
    }

    # STEP 5: The owner (alice) creates a team and the two team keys.
    # (STEP 3 and 4, the first diffie-hellman exchange and the aes-gcm encrypted messages,
    # happen inside every command from here on.)
    python client.py alice create-team blue

    # STEP 5: Second diffie-hellman exchange, between the owner and the team member (bob),
    # with the server acting as an intermediary. The shared key is used to encrypt the two
    # team keys, and bob decrypts them with the same shared key.
    python client.py alice invite bob --yes
    python client.py bob join blue --yes

    # STEP 6 and 7: The owner protects the dataset with the team keys and sends it. The
    # server scores each row as suspicious or not flagged and signs the verdict.
    python client.py alice send

    # STEP 8: The team member fetches the dataset and decrypts the encrypted columns
    # using the team keys. (Only the first rows are shown here.)
    python client.py bob fetch | Select-Object -First 12

    # carol is registered, but she is not in the team, so the server refuses her.
    $ErrorActionPreference = "Continue"
    python client.py carol join blue --yes
    $ErrorActionPreference = "Stop"

    # This shows what the server stored for one row: the pseudonym and the encrypted
    # package name (which the server can't read), and the columns that were left readable.
    python -c "import json; d = json.load(open(r'$temp\server\data.json')); r = list(d['rows']['blue'].values())[0]['row']; print('package_pseudonym:', r['package_pseudonym']); print('package_encrypted:', r['package_encrypted'][:50] + '...'); print('readable:', r['version'], '|', r['published'], '| followers', r['followers_range'])"
}
finally {
    # Stops the server and deletes the temporary folders.
    if ($server) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item Env:SECURE_SHARE_HOME, Env:SECURE_SHARE_SERVER_DIR -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    if (Test-Path $temp) { Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue }
}
