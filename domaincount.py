import csv, re, collections, time, glob, sys
from urlparse import urlparse
from itertools import islice

multitld=['co.uk', 'wa.gov', 'us.mil']
symbol = "~`!@#$%^&*()_-+={}[]:>;',</?*-+"
timestr = time.strftime("%Y%m%d-%H")
timestamp = time.strftime("%Y%m%d-%H%M%S")
output_name = 'results'+ timestamp +'.txt'
deny = ['TCP_DENIED']
allow = ['TCP_MISS', 'TCP_HIT', 'UDP_HIT', 'TCP_REFRESH_HIT', 'TCP_CLIENT_REFRESH_MISS', 'TCP_MEM_HIT', 'TCP_IMS_HIT']
alldomains=[]
denydomains=[]
allowdomains=[]
unknowndomains=[]
errordomains=[]
	
def main(argv):
	list_of_files = glob.glob(argv[1])
	for fileName in list_of_files:
		with open(fileName) as myfile:
			head = list(islice(myfile, 5))
		if 'sc-result-code' in head[4]:
			w3c(fileName)
		else:
			print 'SQUID'
	print collections.Counter(alldomains)
		

def w3c(fileName):
		print 'Processing ' + fileName
		file = open( fileName, "r" ).readlines()
		for row in csv.reader(file, delimiter=" "):
			try:
				if row[0].startswith('#') or row[8] is None:
					continue
				url = urlparse(row[8])
				#Remove port if defined (e.g. :443)
				domain = url.netloc.split(':',1)[0]
				#Split domain name on '.'
				tld = domain.rsplit('.',3)
				#Ignore anything with 1 or less values or first value is a special character
				if len(tld) <= 1 or tld[-1] in symbol:
					continue
				#For domains known domains larger than 2 levels (e.g. '.co.uk')
				elif tld[-2] + '.' + tld[-1] in multitld and row[18] in allow:
					alldomains.append(tld[-3] + '.' + tld[-2] + '.' + tld[-1])
					allowdomains.append(tld[-3] + '.' + tld[-2] + '.' + tld[-1])
				elif tld[-2] + '.' + tld[-1] in multitld and row[18] in deny:
					alldomains.append(tld[-3] + '.' + tld[-2] + '.' + tld[-1])
					denydomains.append(url.netloc + ' ' + row[18] + ' ' + row[17])
				elif tld[-2] + '.' + tld[-1] in multitld and row[18] == 'NONE':
					alldomains.append(tld[-3] + '.' + tld[-2] + '.' + tld[-1])
					errordomains.append(url.netloc + ' ' + row[18] + ' ' + row[17])
				#For values that are IP address'
				elif number(tld[-1]) == True and row[18] in allow:
					alldomains.append(tld[-4] + '.' + tld[-3] + '.' + tld[-2] + '.' + tld[-1])
					allowdomains.append(tld[-4] + '.' + tld[-3] + '.' + tld[-2] + '.' + tld[-1])
				elif number(tld[-1]) == True and row[18] in deny:
					alldomains.append(tld[-4] + '.' + tld[-3] + '.' + tld[-2] + '.' + tld[-1])
					denydomains.append(url.netloc + ' ' + row[18] + ' ' + row[17])
				elif number(tld[-1]) == True and row[18] == 'NONE':
					alldomains.append(tld[-4] + '.' + tld[-3] + '.' + tld[-2] + '.' + tld[-1])
					errordomains.append(url.netloc + ' ' + row[18] + ' ' + row[17])
				#For most domains (e.g. 'google.com')
				elif row[18] in allow:
					alldomains.append(tld[-2] + '.' + tld[-1])
					allowdomains.append(tld[-2] + '.' + tld[-1])
				elif row[18] in deny:
					alldomains.append(tld[-2] + '.' + tld[-1])
					denydomains.append(url.netloc + ' ' + row[18] + ' ' + row[17])
				elif row[18] == 'NONE':
					alldomains.append(tld[-2] + '.' + tld[-1])
					errordomains.append(url.netloc + ' ' + row[18] + ' ' + row[17])
				elif number(tld[-1]) == True:
					unknowndomains.append(url.netloc + ' '  + row[18] + ' ' + row[17])
				else:
					alldomains.append(tld[-2] + '.' + tld[-1])
					unknowndomains.append(url.netloc + ' '  + row[18] + ' ' + row[17])
					print row[18]
			except:
				print url.netloc + 'EXCEPT'
				continue
		#Sort and count unique values
		counter = collections.Counter(alldomains)
		with open('all_' + output_name, "w") as f:
			for k,v in  counter.most_common():
				f.write( "{} {}\n".format(k,v) )
		counter = collections.Counter(allowdomains)
		with open('allow_' + output_name, "w") as f:
			for k,v in  counter.most_common():
				f.write( "{} {}\n".format(k,v) )
		counter = collections.Counter(denydomains)
		with open('deny_' + output_name, "w") as f:
			for k,v in  counter.most_common():
				f.write( "{} {}\n".format(k,v) )
		counter = collections.Counter(unknowndomains)
		with open('unknown_' + output_name, "w") as f:
			for k,v in  counter.most_common():
				f.write( "{} {}\n".format(k,v) )
		counter = collections.Counter(errordomains)
		with open('error_' + output_name, "w") as f:
			for k,v in  counter.most_common():
				f.write( "{} {}\n".format(k,v) )
	


def number(s):
    try: 
        int(s)
        return True
    except ValueError:
        return False
		
main(sys.argv)