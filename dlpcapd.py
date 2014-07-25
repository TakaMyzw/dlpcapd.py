## PCAP Exporter for PANW next generation Firewall
##
## This is a daemon to export PCAP file from PANW next generation firewall
## for queued threat log entries in a persistent queue. This works with a
## syslog receiver "psyslog.py" through a persistent queue.
## 
## This progam requires following python library:
## 1. persistent queue | https://gist.github.com/wolever/1857838
## 2. daemonize | https://github.com/thesharp/daemonize
## 3. API handler for PANW firewall | https://github.com/TakaMyzw/panapi.py.git
#

from panapi import PANWAPIHandler
from pqueue import PersistentQueue
from daemonize import Daemonize
import xml.etree.ElementTree as ET
import pytz
import datetime
import time
import os
import csv
import logging
import types

HostInfo = [[str(elm) for elm in v] for v in csv.reader(open("hostconfig.txt", "r"))]
parameters = ''
pcapdir = '/var/tmp/pcap'

pid = "/var/run/dlpcapd.pid"
logger = logging.getLogger(__name__)
#logger.basicConfig(format=log_fmt)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger.setLevel(logging.DEBUG)
logger.propagate = False
fh = logging.FileHandler("/var/log/dlpcap.log", "w")
fh.setFormatter(formatter)
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
keep_fds = [fh.stream.fileno()]

logger.debug("Initialize start")
logger.debug("HostInfo = %s", HostInfo)
for elem in HostInfo:
	elem.append(PANWAPIHandler(elem[1],parameters))

	elem[2].key()

	xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system"
	config_result = elem[2].config("get",xpath)
	timezone = config_result.find('./result/system/timezone').text
	local = pytz.timezone (timezone)
	elem.append(local)

	logger.debug(elem)
logger.debug("Initialize end")

interval = 0.5

def main():
	logger.debug("main routine start")

	while True:
		q2 = PersistentQueue("/var/tmp/queue_storage_dir")
		if q2.qsize():
			try:
				queue = q2.get()
				logger.debug(queue)
				pcap_info = queue.split(',')
				logger.debug(pcap_info)
	
				for i in HostInfo:
					re = pcap_info[0] in i
					if re:
						logger.debug("queued item and hostinfo matched!")
						unix_t = (int(time.mktime(time.strptime(pcap_info[1], '%Y/%m/%d %H:%M:%S'))))
	
						if len(pcap_info) == 4:
						# 6.0
							exp_params = {'category': 'threat-pcap', 'serialno': pcap_info[0], 'pcapid': pcap_info[3], 'search-time': pcap_info[1]}
							pcaplocalpath = str.rstrip(pcap_info[0]) + '-' + str(unix_t) + '-' + str.rstrip(pcap_info[2]) + '-' + str.rstrip(pcap_info[3]) + '.pcap'
						else:
	#						logger.debug( i
	#						logger.debug( pcap_info[1]
	#						logger.debug( pcap_info[2]
							naive = datetime.datetime.strptime(pcap_info[1], "%Y/%m/%d %H:%M:%S")
	#						logger.debug( naive
							local_dt = i[3].localize(naive, is_dst=None)
							utc_dt = local_dt.astimezone(pytz.utc)
							utc_d = utc_dt.strftime("%Y%m%d")
	#						logger.debug( utc_dt
	#						logger.debug( utc_d
							pcapfilepath = str(utc_d) + '/' + str(unix_t) + '-' + str.rstrip(pcap_info[2]) + '.pcap'
							logger.debug(pcapfilepath)
							exp_params = {'category': 'threat-pcap', 'from': pcapfilepath}
							pcaplocalpath = str.rstrip(pcap_info[0]) + '-' + str(unix_t) + '-' + str.rstrip(pcap_info[2]) + '.pcap'
	
						logger.debug("download pcap")
	#					response_pcap = i[2].export('threat-pcap',pcapfilepath)
						response_pcap = i[2].export(exp_params)
						logger.debug("download finished")
						logger.debug(type(response_pcap))
						if isinstance(response_pcap, str):
							outfile = open(pcapdir + '/' + pcaplocalpath, 'w')
							outfile.write(response_pcap)
							outfile.close()
						elif isinstance(response_pcap,ET.Element):
							logger.debug(ET.tostring(response_pcap))
						logger.debug('download finished')
						logger.debug('pcap file close')
						logger.debug('a pcap saved to ' + pcapdir + '/' + pcaplocalpath)
						interval = 0.5
						break
	
			except Exception as e:
				logger.debug("error information")
				logger.debug('type:' + str(type(e)))
				logger.debug('args:' + str(e.args))
				logger.debug('message:' + e.message)
				logger.debug('e itself:' + str(e))
				logger.debug("rollback a queue")
				q2.put(queue)
		else:
			logger.debug("change interval to 10 second as there is no queue entry")
			interval = 10	
		q2.close
		time.sleep(interval)

daemon = Daemonize(app="dlpcapd", pid=pid, action=main, keep_fds=keep_fds)
daemon.start()
