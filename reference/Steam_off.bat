REM Allow ip range 192.0.0.1-192.168.2.249 and 254.254.254.254(allow broadcast for steamlink to find server) block all other ip addresses.
netsh advfirewall firewall add rule name="_01 Block steam(Program)" dir=in remoteip=0.0.0.0-191.254.254.254 program="C:\Program Files (x86)\Steam\steam.exe" action=block
netsh advfirewall firewall add rule name="_01 Block steam(Program)" dir=in remoteip=192.168.2.250-254.254.254.253 program="C:\Program Files (x86)\Steam\steam.exe" action=block
netsh advfirewall firewall add rule name="_01 Block steam(Program)" dir=out remoteip=0.0.0.0-191.254.254.254 program="C:\Program Files (x86)\Steam\steam.exe" action=block
netsh advfirewall firewall add rule name="_01 Block steam(Program)" dir=out remoteip=192.168.2.250-254.254.254.253 program="C:\Program Files (x86)\Steam\steam.exe" action=block

