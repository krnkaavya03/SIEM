"""
test_winrm.py — run this directly:
    python test_winrm.py
"""
import winrm

SERVER   = "192.168.1.3"
USERNAME = "krnka"
PASSWORD = "rkrp*skl=kkvy"   # ← your password is already here
CHANNEL  = "Security"

print(f"\nConnecting to {USERNAME}@{SERVER} ...")

session = winrm.Session(
    f"http://{SERVER}:5985/wsman",
    auth=(USERNAME, PASSWORD)
)

# Step 1: simple connectivity test
r = session.run_ps("echo 'WinRM OK'")
print("Connectivity:", r.std_out.decode().strip() or "NO OUTPUT")
if r.std_err:
    print("ERR:", r.std_err.decode().strip())

# Step 2: pull 3 raw events with ISO timestamp
ps = """
$events = Get-WinEvent -LogName 'Security' -MaxEvents 3 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output 'NO_EVENTS'; exit }
$events | ForEach-Object {
    $t = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
    Write-Output "$t | ID=$($_.Id)"
}
"""
r2 = session.run_ps(ps)
print("\nRaw events:")
print(r2.std_out.decode().strip() or "EMPTY")
if r2.std_err:
    print("ERR:", r2.std_err.decode().strip())

# Step 3: full JSON pull (what the SIEM uses)
ps2 = """
$events = Get-WinEvent -LogName 'Security' -MaxEvents 5 -ErrorAction SilentlyContinue
if (-not $events) { Write-Output '[]'; exit }
$result = $events | ForEach-Object {
    [PSCustomObject]@{
        TimeStr = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        Id      = $_.Id
    }
}
$result | ConvertTo-Json -Compress
"""
r3 = session.run_ps(ps2)
print("\nJSON output:")
print(r3.std_out.decode().strip()[:500] or "EMPTY")
if r3.std_err:
    print("ERR:", r3.std_err.decode().strip())

print("\nDone.")