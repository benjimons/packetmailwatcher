#!/usr/bin/env python
import ConfigParser
import datetime, pprint
import urllib, json
import sqlite3
import sys
from email.mime.text import MIMEText
from subprocess import Popen, PIPE

config = ConfigParser.RawConfigParser()
cfgfile = sys.argv[1]

config.read(cfgfile)
dir = config.get('Global', 'dir')
apikey = config.get('Global', 'apikey')
fromaddr = config.get('Global', 'fromaddr')

subnet = sys.argv[2]
subnetnoslash = subnet.replace("/","-")
mailto = sys.argv[3]

#connect to DB - create one if it does not exist
conn = sqlite3.connect(dir+'/dbs/pmdb-'+subnetnoslash+'.db')
c = conn.cursor()

# Create table if not exists
c.execute('''CREATE TABLE if not exists reps
             (ip text, engine text, source text, context text, last_seen text, refreshed text)''')

conn.commit()

#reset the variables
msgstring=""
newcounter=0
counter=0

#retrieve the dumps from Ryans dump service
url = "https://www.packetmail.net/iprep_cidr.php/"+subnet+"?apikey="+apikey
response = urllib.urlopen(url)
data1 = json.loads(response.read())

#go through the results(rows) and work out what is new
thisip="0"
try:
	for dic in data1:

		for key in dic:
			if key == "disclaimer":
				continue

			if key == "_id":
				thisip = dic[key]

			if 'source' in dic[key]:
				thisip = dic['_id']
				context = str(dic[key]['context'])
				source = dic[key]['source']
				last_seen = dic[key]['last_seen']
				refreshed = dic[key]['refreshed']
				#Work out if we already saw this IP and context before
				c.execute("SELECT * FROM reps where ip=? and engine=? and source=? and context=?", (thisip, key, source, context))
				conn.commit()				
				counter+=1
				#if we didnt find this entry in the database, enter it and build a string for the email notification
				if len(c.fetchall()) == 0:
					c.execute("INSERT into reps (ip, engine, source, context) VALUES (?,?,?,?)", (thisip, key, source, context))
				        conn.commit()
					newstring = "IP:"+thisip+" Source "+key+" context: "+context+"\r\n"
					#print newstring
					msgstring += newstring
					newcounter+=1
except KeyError:
	#none found
	error=1
except :
	with open(dir+"/logs/pm-"+subnetnoslash+".log", "a+") as logfile:
		logfile.write(sys.exc_info()[0])
	print "Unexpected error:" , sys.exc_info()[0]
#email the new results
if newcounter > 0:
	msg = MIMEText(msgstring)
	msg["From"] = fromaddr
	msg["To"] = mailto
	msg["Subject"] = "Packetmail Watcher new threat intel on "+subnet
	p = Popen(["/usr/sbin/sendmail", "-t", "-oi"], stdin=PIPE)
	p.communicate(msg.as_string())	
	
with open(dir+"/logs/pm-"+subnetnoslash+".log", "a+") as logfile:
	logfile.write(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))+" Packetmail - "+str(counter)+" entries found for "+subnet+", "+str(newcounter)+" new\n\r")

#print(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))+" CheckMyDump - "+str(counter)+" entries found for "+domain+", "+str(newcounter)+" new")

conn.close()
