import winrm
SERVER   = '192.168.1.3'
USERNAME = 'DESKTOP-ABC123\\krnka'
PASSWORD = 'rkrp*skl=kkvy'
session  = winrm.Session(transport='basic', 'http://' + SERVER + ':5985/wsman', auth=(USERNAME, PASSWORD))
r1 = session.run_ps('echo WinRM_OK')
print('Step1:', r1.std_out.decode().strip(), r1.std_err.decode().strip())
r2 = session.run_ps('Get-WinEvent -LogName Security -MaxEvents 3 | ForEach-Object { Write-Output (.TimeCreated.ToString(''yyyy-MM-dd HH:mm:ss'') + '' ID='' + .Id) }')
print('Step2:', r2.std_out.decode().strip())
print('ERR2:', r2.std_err.decode().strip())
