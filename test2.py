import winrm
session = winrm.Session('http://192.168.1.3:5985/wsman', auth=('siemuser', 'SIEMpass123!'), transport='basic')
r = session.run_ps('echo WinRM_OK')
print('Result:', r.std_out.decode().strip())
print('Error:', r.std_err.decode().strip())
