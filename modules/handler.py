#!/usr/bin/python
import os, sys, time
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

default10 = "yes"
port = "4444"

print "\033[1;94m[?]\033[1;m LPORT :: Port Number to listen on for connection"
portNumber = raw_input('\033[1;92m[+]\033[1;m port: [' + port + ']: ') or port

print "\033[1;94m[?]\033[1;m Configuring Plugin"
time.sleep(1)
print ""
print "Name             Set Value"
print "----             ----------"
print "LPORT            %s" % (portNumber)
print "Plugin           Handler"
print "\n"
et = raw_input("\033[1;94m[?]\033[1;m Execute Plugins? [" + default10 + "]: ")  or default10
if et == 'yes':
	print "Spawning listener on", portNumber
	os.system('sudo netcat -lvp ' + portNumber)
elif et == 'no':
    print "Goodbye ;("
    sys.exit()
else:
    print "\033[1;92m[!] No options were chosen.\033[1;m"