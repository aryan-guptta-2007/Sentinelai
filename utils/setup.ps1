# Set up SentinelAI on Windows. Safe to run more than once.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

if (-not (Test-Path '.venv')) {
    py -3.11 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create .venv. Python 3.11 or newer is required.' }
}

& .\.venv\Scripts\python.exe -m pip install --quiet --upgrade pip
& .\.venv\Scripts\python.exe -m pip install --quiet -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Installing requirements failed.' }

& .\.venv\Scripts\python.exe sentinel.py check

Write-Host ''
Write-Host 'Setup finished. Start the demo with:'
Write-Host '  .\.venv\Scripts\python.exe sentinel.py demo'
