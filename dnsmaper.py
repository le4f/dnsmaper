#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
 ____  _   _ ____  __  __
|  _ \| \ | / ___||  \/  | __ _ _ __   ___ _ __
| | | |  \| \___ \| |\/| |/ _` | '_ \ / _ \ '__|
| |_| | |\  |___) | |  | | (_| | |_) |  __/ |
|____/|_| \_|____/|_|  |_|\__,_| .__/ \___|_|
                               |_|
 =# Author: le4f.net
 =# Mail  : le4f#xdsec.org
'''

import requests
import re
import random
import geoip2.database
import webbrowser
import os,sys
import time
import optparse
import signal
import dns.resolver
import socket
from threading import Thread
import string
try:
    import queue
except:
    import Queue as queue

class lookup(Thread):

    def __init__(self, in_q, out_q, domain, wildcard = False, resolver_list = []):
        Thread.__init__(self)
        self.in_q = in_q
        self.out_q = out_q
        self.domain = domain
        self.wildcard = wildcard
        self.resolver_list = resolver_list
        self.resolver = dns.resolver.Resolver()
        if len(self.resolver.nameservers):
            self.backup_resolver = self.resolver.nameservers
        else:
            #we must have a resolver,  and this is the default resolver on my system...
            self.backup_resolver = ['127.0.0.1']
        if len(self.resolver_list):
            self.resolver.nameservers = self.resolver_list

    def check(self, host):
        slept = 0
        while True:
            try:
                answer = self.resolver.query(host)
                if answer:
                    return str(answer[0])
                else:
                    return False
            except Exception as e:
                if type(e) == dns.resolver.NXDOMAIN:
                    return False
                elif type(e) == dns.resolver.NoAnswer  or type(e) == dns.resolver.Timeout:
                    if slept == 4:
                        if self.resolver.nameservers == self.backup_resolver:
                            self.resolver.nameservers = self.resolver_list
                        else:
                            self.resolver.nameservers = self.backup_resolver
                    elif slept > 5:
                        self.resolver.nameservers = self.resolver_list
                        return False
                    time.sleep(1)
                    slept += 1
                elif type(e) == IndexError:
                    pass
                else:
                    #raise e
					pass

    def run(self):
        while True:
            sub = self.in_q.get()
            if not sub:
                self.in_q.put(False)
                self.out_q.put(False)
                break
            else:
                test = "%s.%s" % (sub, self.domain)
                addr = self.check(test)
                if addr and addr != self.wildcard:
                    self.out_q.put(test)

def ReadFile(FilePath,WriteType):
	ReadFile = open(FilePath, WriteType)
	FileC = ReadFile.readlines()
	i = 0
	while i < len(FileC):
		FileC[i] = FileC[i].strip()
		i +=1
	ReadFile.close()
	return FileC

def WriteFile(LogSource,LogFilePath,WriteType):
	LogCnt = ''
	if type(LogSource) == type(list()):
		for line in LogSource:
			LogCnt += line.encode('utf8') + '\n'
	else:
		LogCnt = LogSource.encode('utf8')+'\n'
	LogCnt += "\n"
	File = open(LogFilePath, WriteType)
	File.write(LogCnt)
	File.close()
'''
在线请求,数量限制
def IpToAddress(ip):
	url = "https://geoip.maxmind.com/geoip/v2.0/city_isp_org/%s?demo=2" % (ip,str(i))
	global LogList
	req = requests.get(url,timeout=7).content
	(longitude,latitude) = re.findall('tude":([\-0-9]+)',req)
	organization = re.findall('organization":"([^"]+)"',req)[0]
	out = u"{Ip:'%s',Longitude:'%s',Latitude:'%s',organization:'%s'}" % (ip,longitude,latitude,organization)
	LogList.append(out)
	print u"[+]IP:\t%s\t  经度: %s  纬度: %s  所有者: %s" % (ip,longitude,latitude,organization)
'''

def GetUrlInfo(url):
	url = "http://"+url
	try:
		r = requests.get(url,timeout=5)
		r.encoding =  r.apparent_encoding
		title = re.findall("<title>(.*)</title>",r.text)[0].replace('\r','').replace('\n','').replace('\r','').replace(' ','')
		banner = ''
		try:
			banner += r.headers['Server']
		except:
			pass
		try:
			banner += r.headers['X-Powered-By']
		except:
			pass
		return (title,banner)
	except:
		return (u"None"),(u"None")
'''
 中文Center补丁
'''
def len_zh(data):
    delset = string.punctuation
    data = data.encode('utf8').translate(None,delset).decode('utf8')
    temp = re.findall('[^a-zA-Z0-9.]+',data)
    count = 0
    for i in temp:
        count += len(i)
    return(count)

def DomainToAddress(domain):
	global LogList
	global result
	try:
		ip=socket.getaddrinfo(domain, None)[0][4][0]
	except:
		print " URI:%-20s RtnIp Error." % domain
		return
	GeoDB = geoip2.database.Reader('./db/GeoLite2-City.mmdb')
	try:
		res = GeoDB.city(ip)
		address = res.country.name + " " + res.city.name
		latitude = res.location.latitude
		longitude = res.location.longitude
		gps = str(latitude)[0:5]+"/"+str(longitude)[0:5]
		(title,banner) = GetUrlInfo(domain)
		out = u"{Ip:'%s %s',Longitude:'%s',Latitude:'%s'}" % (ip,title,longitude,latitude)
		log = u"%s\t%s\t%s\t%s\t%s\t%s" % (domain,ip,title,banner,address,gps)
		LogList.append(out)
		LogFile.append(log)
		title = title[0:13]
		print "|%s|%s|%s|%s|%s|%s|" % (domain.split('.')[0][0:9].center(9),ip[0:17].center(17),title.center(28-len_zh(title)),banner[0:28].center(28),address[0:14].center(14),gps[0:11].center(11))
		print "+---------+-----------------+----------------------------+----------------------------+--------------+-----------+"
	except Exception,e:
		pass
	finally:
		GeoDB.close()

def SaveMap(log,logfile):
    f = open(logfile,'w')
    content = """
    <html>
    <!--Generated By DNSMaper-->
      <head>
        <style>
        body { font-family: Helvetica; }
        .map-content h3 { margin: 0; padding: 5px 0 0 0; }
        </style>
        <script type="text/javascript" src="http://maps.googleapis.com/maps/api/js?sensor=true"></script>
        <script>
        // Set the Map variable
            var map;
            function initialize() {
                var myOptions = {
                zoom: 2,
                mapTypeId: google.maps.MapTypeId.ROADMAP
            };
            var MessAge="[%s]"
                var all=eval(MessAge);
            var infoWindow = new google.maps.InfoWindow;
            map = new google.maps.Map(document.getElementById('map_canvas'), myOptions);
            // Set the center of the map
            var latitude=30.35;
            var longitude=114.17;
            var pos = new google.maps.LatLng(latitude, longitude);
            map.setCenter(pos);
            function infoCallback(infowindow, marker) {
                return function() {
                infowindow.open(map, marker);
            };
       }
       function setMarkers(map, all) {
        for (var i in all) {
                var ip 	    = all[i].Ip;
                var lat 	= all[i].Latitude;
                var lng 	= all[i].Longitude;
                for(var j=0;j<i;j++){
                if((all[j].Latitude == lat)||(all[j].Longitude == lng)){
                ip=ip+'<br/>'+all[j].Ip;
                }
                }
                var latlngset;
                latlngset = new google.maps.LatLng(lat, lng);
                var marker = new google.maps.Marker({
                  map: map,
                  position: latlngset
                });
                var content = '<div class="map-content">'+ ip+ '<br/><br/>'+'纬度:' +lat + '<br/>'+'经度:' + lng + '</div>';
                var infowindow = new google.maps.InfoWindow();
                  infowindow.setContent(content);
                  google.maps.event.addListener(
                    marker,
                    'click',
                    infoCallback(infowindow, marker)
                  );
              }
            }
            // Set all markers in the all variable
            setMarkers(map, all);
          };
          // Initializes the Google Map
          google.maps.event.addDomListener(window, 'load', initialize);
        </script>
      </head>
      <body>
        <div id="map_canvas" style="height: 610px; width: 1030px;"></div>
      </body>
    </html>
    """ % log
    f.write(content)

def killme(signum = 0, frame = 0):
    global LogList,LogFile,LogFN,LogMapN
    WriteFile(LogFile,LogFN,'w')
    logs = ''
    for log in LogList:
         logs += log + ','
    SaveMap(logs.encode('utf8'),LogMapN)
    print "[!]Save Map: %s" % LogMapN
    webbrowser.open_new_tab("file://"+os.getcwd()+"/log/"+target+".html")
    print "[*]Exit."
    os.kill(os.getpid(), 9)

def check_resolvers(file_name):
    ret = []
    resolver = dns.resolver.Resolver()
    res_file = open(file_name).read()
    for server in res_file.split("\n"):
        server = server.strip()
        if server:
            resolver.nameservers = [server]
            try:
                resolver.query("www.google.com")
                ret.append(server)
            except:
                pass
    return ret

def run_target(target, hosts, resolve_list, thread_count):
    wildcard = False
    try:
        resp = dns.resolver.Resolver().query("would-never-be-a-fucking-domain-name-" + str(random.randint(1, 9999)) + "." + target)
        wildcard = str(resp[0])
    except:
        pass
    in_q = queue.Queue()
    out_q = queue.Queue()
    for h in hosts:
        in_q.put(h)
    in_q.put(False)
    step_size = int(len(resolve_list) / thread_count)
    if step_size <= 0:
        step_size = 1
    step = 0
    for i in range(thread_count):
        threads.append(lookup(in_q, out_q, target, wildcard , resolve_list[step:step + step_size]))
        threads[-1].start()
    step += step_size
    if step >= len(resolve_list):
        step = 0

    threads_remaining = thread_count
    while True:
        try:
            d = out_q.get(True, 10)
            if not d:
                threads_remaining -= 1
            else:
                DomainToAddress(d)

        except queue.Empty:
            pass
        if threads_remaining <= 0:
            break

'''
	域传送漏洞检测,适用Linux环境
'''
def dns_zone_transfer_check(domain):
	cmd_res = os.popen('nslookup -type=ns ' + domain).read()
	dns_servers = re.findall('nameserver = ([\w\.]+)', cmd_res)
	for server in dns_servers:
		if len(server) < 5: server += domain
		cmd_res = os.popen('dig @%s axfr %s' % (server, domain)).read()
		if cmd_res.find('Transfer failed.') < 0 and cmd_res.find('connection timed out') < 0 and cmd_res.find('XFR size') > 0 :
			print '[!]Vulnerable DNS Zone Transfer Found: %s' % server
			print cmd_res
		else:
			print '[!]DNS Zone Transfer UnVulnerable.'

if __name__ == '__main__':
    print __doc__
    parser = optparse.OptionParser("Usage: %prog [options] target")
    parser.add_option("-c", "--thread_count", dest = "thread_count",
              default = 17, type = "int",
              help = "[optional]number of lookup theads,default=17")
    parser.add_option("-s", "--subs", dest = "subs", default = "./db/subs.db",
              type = "string", help = "(optional)list of subdomains,  default='./db/subs.db'")
    parser.add_option("-r", "--resolvers", dest = "resolvers", default = "./db/resolvers.db",
              type = "string", help = "(optional)list of DNS resolvers,default='./db/resolvers.db'")
    (options, args) = parser.parse_args()
    LogList = []
    LogFile = []
    if len(args) < 1:
        print ("[-]Target Plz! Use -h for help.")
        exit(1)
    targets = args
    for target in targets:
        target = target.strip()
	dns_zone_transfer_check(target)
    LogFN = './log/'+target+'.log'
    LogMapN = './log/'+target+'.html'
    hosts = open(options.subs).read().split("\n")
    print '\n[!]Check DNS Resolvers..'
    resolve_list = check_resolvers(options.resolvers)
    threads = []
    signal.signal(signal.SIGINT,killme)
    print '\n[!]BruteForce NS Name..\n'
    print "+---------+-----------------+----------------------------+----------------------------+--------------+-----------+"
    print "|   NS    |        IP       |           Title            |           Server           |    Address   |    GPS    |"
    print "+---------+-----------------+----------------------------+----------------------------+--------------+-----------+"
    run_target(target, hosts, resolve_list, options.thread_count)
    WriteFile(LogFile,LogFN,'w')
    logs = ''
    for log in LogList:
        logs += log + ','
    SaveMap(logs.encode('utf8'),LogMapN)
    print "[!]Save Map: %s" % LogMapN
    webbrowser.open_new_tab("file://"+os.getcwd()+"/log/"+target+".html")
    print "[*]All Done."