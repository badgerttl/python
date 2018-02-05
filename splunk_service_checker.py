#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Script to check Splunk is running on remote *nix systems and start it if not. 

Requires paramiko to be installed.
'''
import paramiko
import re
import smtplib
import time
import StringIO
import socket
from email.mime.text import MIMEText
local_host = socket.gethostname()

def main():
	check = '/opt/splunk/bin/splunk status'
	hosts = ['']
	i = 0
	mailto = ''
	reservice = re.compile('^splunkd\sis\srunning\s\(PID:\s\d+\)\.')
	service = 'Splunk'
	start = '/opt/splunk/bin/splunk start'
	
	for host in hosts:
		#Runs command to get status of process
		stdin, stdout, stderr = sshconnection(host, check)
		if stderr != 1:
			status = stdout.readlines()
			#Reviewing results of check to see if process is running. 
			#If not, sets results to 1 for further work
			if filter(reservice.search, status):
				email(host+'', mailto, 
					  service+' service is running on '+host,
					  service+' service is running on '+host)
				print "Running"
				result = 0
			else:		
				print "Not Running"
				result = 1
			#While loop to start service and verify it has started
			while (result == 1) and (i < 10):
				email(host+'@', mailto,
					  service+' service has stopped running on '+host,
					  service+' service has stopped running on '\
					  +host+'\n\n\tAttempting to start service ('+str(int(i)+1)+' of 10)')
				stdin, stdout, stderr = sshconnection(host, start)
				time.sleep(30)
				stdin, stdout, stderr = sshconnection(host, check)
				status = stdout.readlines()
				if filter(reservice.search, status):
					email(host+'@', mailto,
						  service+' service is running on '+host,
						  service+' service is running on '+host)
					print "Running"
					result = 0
				else:		
					print "Not Running"
					result = 1
				i += 1
	
def sshconnection(host, cmd):
	'''
	Setup SSH session to remote machine.  
	
	Requires remote host and command to execute	on remote system
	'''
	
	pri_key = ''
	user = ''
	f = open(pri_key,'r').read()
	keyfile = StringIO.StringIO(f)
	mykey = paramiko.RSAKey.from_private_key(keyfile)
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		ssh.connect(host, username=user, pkey=mykey)
	except Exception, e:
		print local_host+"\t"+str(e)+" at "+host
		return "", "", 1
	stdin, stdout, stderr = ssh.exec_command(cmd)
	return stdin, stdout, stderr
	ssh.close()
	
	
def email(fr, to, subject, message):
	'''
	Setup mail server and send email for alerting or notifications.
	
	Requires from address, to address, subject line, and mail message
	'''
	smtpserver = ''
	try:
		mailserver = smtplib.SMTP(host=smtpserver)
	except Exception, e:
		print local_host+"\t"+str(e)
		return 1
	msg = MIMEText(message)
	msg['From'] = fr
	msg['To'] = to
	msg['Subject'] = subject
	mailserver.sendmail(msg['From'], msg['To'], msg.as_string())
	mailserver.quit()
	
main()