#!/usr/bin/env python3

import subprocess
from termcolor import colored
import os
import threading
import time
import argparse
import shutil
import signal,sys
import socket
import re,configparser

# (.*)(?:\?) --> Matches the url part, ie before the ?
# (?:\?)(\w+)(?:=)  --> Matches the first occurence after the ?
# (?:\&)(\w*)       --> Matches After the & [i,e second parameter]

'''
TODO
Add Shebangs to programs that don't have it + give it executable permission
Add the programs to env path so that it can be executed from anywhere
Modify the commands as per your needs
'''


'''
pip install termcolor

PREREQ TOOLS

assetfinder
sublister


httprobe
aquatone
getallurl
waybackurl
waybackrobot
vhostdsicovery
gitallsecret
subjack
subHijack
spfspoof
waaf

'''
DEVNULL = open(os.devnull,"w")

def banner():
	x="""
		_  _ _ _    _    ____ ____   ____ ____ ___ 
		|_/  | |    |    |___ |__/   |  | |  |   /
		| \\_ | |___ |___ |___ |  \\   |__| |__|  /  
      """


 
	y = "		+-----------------------------------------+"     
	z = "							~~Twitter: Killeroo7p\n\n"
	print(colored(x,'blue'))
	print(colored(y,'red'))
	print(colored(z,'green'))

def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-u','--url',dest='url',required=True,help="Specify URL")
	parser.add_argument('-c','--cookie',dest='cookie',help="Use Cookies[value=param;]")
	parser.add_argument('-o','--output',dest='output',help="Output Location")
	parser.add_argument('-p','--phase',dest='start_phase',type=int,help="Start The Program from a Specific Phase")
	parser.add_argument('-g','--gau-single',dest='gau_single',action='store_true',help="Run gau on the main domain only")
	parser.add_argument('-a','--amass',dest='amass', action='store_true',help="Ignore Amass")

	args = parser.parse_args()
	return args

def create_unique_directory(url):
	directory = url+"{}"
	counter = 0
	while os.path.exists(directory.format(counter)):
	    counter += 1
	directory = directory.format(counter)
	os.mkdir(directory)
	os.chdir(directory)

def time_status(Program,seconds):
	start_time = time.time()
	global aquatone_finished
	while True:
		if aquatone_finished == True:
			break
		if time.time() > start_time + seconds:
			print(colored("[+] "+Program+" is still running",'cyan'))
			break

def signal_handler(signal, frame):
  print(colored("\n\nExitting.... BYE BYE\n","cyan"))
  sys.exit(0)


def filter_duplicate_domains(x):
  return list(dict.fromkeys(x))


def check_file_exist(fpath):  
    return os.path.isfile(fpath) and os.path.getsize(fpath) > 0


def sublister(url):
	print(colored("[+] Scanning For Subdomains with Sublist3r",'green'))
	sublister_cmd = f"sublist3r -d {url} -o sublister_subs_file"
	with open(os.devnull,'w') as devnull:
		subprocess.call(sublister_cmd,shell=True,stdout=devnull,stderr=devnull)

	print(colored("[+] Sublist3r Scanning Completed",'yellow'))


def assetfinder(url):
	print(colored("[+] Scanning For Subdomains with AssetFinder",'green'))
	asset_cmd = f"assetfinder {url} --subs-only > assetfinder_subs_file"
	with open(os.devnull,'w') as devnull:
		subprocess.call(asset_cmd,shell=True,stdout=devnull)
	
	print(colored("[+] AssetFinder Scanning Completed",'yellow'))


def amass(url):
	print(colored("[+] Scanning For Subdomains with Amass",'green'))
	amass_cmd = f"amass enum -d {url} -o amass_subs_file"
	with open(os.devnull,'w') as devnull:	
		subprocess.call(amass_cmd,shell=True,stdout=devnull,stderr=devnull)
	print(colored("[+] Amass Scanning Completed",'yellow'))


def subfinder(url): 
	print(colored("[+] Scanning For Subdomains with Subfinder",'green'))
	subfinder_cmd = f"subfinder -d {url} -o subfinder_subs_file"
	with open(os.devnull,'w') as devnull:
		subprocess.call(subfinder_cmd,shell=True,stdout=devnull,stderr=devnull)
	print(colored("[+] Subfinder Scanning Completed",'yellow'))


def github_subdomains(url,GITTOKEN):	
	print(colored("[+] Scanning For Subdomains with github-subdomains",'green'))
	cmd_github_subdomains = f"github-subdomains.py -t {GITTOKEN} -d {url} > github_subs_file"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_github_subdomains,shell=True,stderr=devnull)
	print(colored("[+] Github-subdomains Scanning Completed",'yellow'))


def shosubgo(url,SHODANAPI):
	print(colored("[+] Scanning For Subdomains with Shosubgo",'green'))
	cmd_shosubgo = f"shosubgo_linux -d {url} -s {SHODANAPI} > shosubgo_subs_files"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_shosubgo,shell=True,stderr=devnull)
	print(colored("[+] Shosubgo Scanning Completed",'yellow'))


def filter_subs():
		all_subs = []
		try:                                                             #try block coz sometimes sublister gives error which breaks the entire program
			with open ('sublister_subs_file','r') as sublister_subs:
				for line in sublister_subs:
					all_subs.append(line)
		except:
			pass

		try:			
			with open ('assetfinder_subs_file','r') as assetfinder_subs:
				for line in assetfinder_subs:
					all_subs.append(line)
		except:
			pass

		try:			
			with open ('amass_subs_file','r') as amass_subs:
				for line in amass_subs:
					all_subs.append(line)
		except:
			pass

		try:			
			with open ('subfinder_subs_file','r') as subfinder_subs:
				for line in subfinder_subs:
					all_subs.append(line)
		except:
			pass

		try:			
			with open ('github_subs_file','r') as github_subs:
				for line in github_subs:
					all_subs.append(line)
		except:
			pass

		try:			
			with open ('shosubgo_subs_files','r') as shosubgo_subs:
				for line in shosubgo_subs:
					all_subs.append(line)
		except:
			pass


		filtered = filter_duplicate_domains(all_subs)
		with open ('subdomains.txt','w+') as all_subs_file:
			for line in filtered:
				all_subs_file.write(line)

		print(colored("[+] Removed Duplicate Domains",'yellow'))

		try:
			os.remove('amass_subs_file')
		except:
			pass

		try:
			os.remove('assetfinder_subs_file')
			os.remove('subfinder_subs_file')
			os.remove('shosubgo_subs_files')
			os.remove('github_subs_file')
			os.remove('sublister_subs_file')
		except:
			pass



def http_probe():
	file = "httprobe_subdomains.txt"
	print(colored("[+] Started HttProbe on subdomains.txt","green"))
	cmd = "cat subdomains.txt | httprobe > " + file
	subprocess.call(cmd,shell=True)
	print(colored("[+] Httprobe Completed",'yellow'))


def aquatone():
	print(colored("[+] Starting Aquatone[This may take some time] ","green"))
	global aquatone_finished
	aquatone_finished = False
	cmd = "cat httprobe_subdomains.txt | aquatone --out aquatone_results/"
	time_thread = threading.Thread(target=time_status,name='Thread_time',args=(["Aquatone",200])).start()	
	subprocess.call(cmd,shell=True,stdout=DEVNULL)
	aquatone_finished = True 	
	print(colored("[+] Aquatone Scan Completed","yellow"))


def waybackurls(url):
	print(colored("[+] Started Waybackurls ","green"))
	cmd = "waybackurls "+url + " > waybackurl_result"
	subprocess.call(cmd,shell=True)	
	print(colored("[+] Waybackurls Scan Completed","yellow"))


def getallURLs(url,gau_single):
	os.mkdir("ALL_URLS")
	print(colored("[+] Started GetAllURLS(gau) [This may take some time]","green"))
	if gau_single:
		gau_cmd = f"gau {url} > ALL_URLS/gau_results" 
	else:
		gau_cmd = f"cat subdomains.txt | gau > ALL_URLS/gau_results" 

	with open(os.devnull,'w') as devnull:
		subprocess.call(gau_cmd,shell=True,stderr=devnull)	
	print(colored("[+] GetallURLs Scan Completed","yellow"))


def get_url_with_param():

	print(colored("[+] Filtering URLs with Parameters","green"))
	with open("ALL_URLS/gau_results","r") as subfile:
		with open("ALL_URLS/urls_with_parameters","w") as paramfile:
			for line in subfile:
				if "?" and "=" in line:
					paramfile.write(line)
	print(colored("[+] Filtered URLs with Parameters","yellow"))

def get_urls_with_uniq_params():  

	param_wordlist =[]   		#For Parameter Wordlist 
	unique_params=[]     		#List Used For Filtering Purpose
	urls_with_unique_params =[] #List to Store All Unique URLS

	with open("ALL_URLS/urls_with_parameters","r") as file:
		for url in file:
			print(f"[+] {url}")
			url_part = (re.search(r"(.*)(?:\?)",url))
			first_param = (re.search(r"(?:\?)(\w+)(?:=)",url))
			other_params = re.findall(r"(?:\&)(\w*)",url)

			all_items=""

			if first_param and other_params and url_part:   #IF URL Contain More than one parameter

				for item in other_params:             #Extracting other parameters as a list
					all_items +=item

					if item not in param_wordlist:    #Add other parameters to Wordlist File
						param_wordlist.append(item)

					if first_param.group(1) not in param_wordlist:    #Add first parameter to wordlist file
						param_wordlist.append(first_param.group(1))

				total = url_part.group(1)+":"+first_param.group(1)+all_items   #Concatenating as URL:FirstParamOtherPsram
				if total not in unique_params:								   #If the concatenated url not in the unique param
					unique_params.append(total)
					urls_with_unique_params.append(url)


			elif first_param and url_part:							#IF URL Contains Only one parameter
				total = url_part.group(1)+":"+first_param.group(1)

				if first_param.group(1) not in param_wordlist:      #Add first parameter to wordlist file
					param_wordlist.append(first_param.group(1))

				if total not in unique_params:
					unique_params.append(total)
					urls_with_unique_params.append(url)
		

	with open("ALL_URLS/urls_with_unique_params","w") as file:
		for item in urls_with_unique_params:
			file.write(item)

	with open("ALL_URLS/parameter_wordlist","w") as file:
		for item in param_wordlist:
			file.write(item+"\n")

	print(colored("[+] Created Dictionary Unique Parameters","yellow"))
	print(colored("[+] Filtered URLs Containing Unique Parameters","yellow"))


def get_urls_with_http():

	#One liner bash
	# cut -c5- urls_with_parameters |grep "http" | sed -e 's/^/http/' > new_urls_with_http

	urls_with_http=[]
	with open ("ALL_URLS/urls_with_unique_params","r") as file:
		for line in file:
			print(f"[+] {url}")
			if "http" in line[6:]:
				urls_with_http.append(line)


	with open ("ALL_URLS/urls_with_http_in_param","w") as file:
		for line in urls_with_http:
			file.write(line)

	print(colored("[+] Filtered URLs Containing HTTP in Parameters","yellow"))


def waybackrobots(url):
	print(colored("[+] Started Waybackrobots","green"))
	cmd = "waybackrobots "+url
	subprocess.call(cmd,shell=True,stdout=DEVNULL,stderr=DEVNULL)
	print(colored("[+] Waybackrobots Scan Completed","yellow"))
	

def WAF_fingerprint(url):
	url = "https://www."+url
	print(colored("[+] Stated Firewall Fingerprinting[wafw00f]","green"))
	cmd = f"wafw00f {url} -o wafw00f_results"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd,shell=True,stdout=devnull,stderr=devnull)	
	print(colored("[+] Firewall Fingerprinting(wafw00f) Completed","yellow"))	

def virtual_host_discovery(ip,host):
	print(colored("[+] Started Virtual-Host-Discovery","green"))
	subprocess.call("cp /opt/killer_py_programs/recon-007/req_files/vhost_wordlist vhost_wordlist",shell=True)
	cmd = "virtual-host-discovery.rb --ip="+ip+" --host="+host+" --wordlist=vhost_wordlist --output=vhost_results "
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd,shell=True,stdout=devnull,stderr=devnull)	
	os.remove('vhost_wordlist')
	print(colored("[+] Virtual-Host-Discovery Scan Completed","yellow"))

def git_all_secrets(gitToken,org):
	print(colored("[+] Started Git-All-Secrets","green"))
	subprocess.call("systemctl start docker",shell=True)	
	cmd = f"sudo docker run -it abhartiya/tools_gitallsecrets -token={gitToken} -org={org} "
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd,shell=True,stdout=devnull)	
	print(colored("[+] Git-All-Secretss Scan Completed","yellow"))

def spf_validate(url):
	print(colored("[+] Started SPF Validation","green"))
	cmd = "spoofcheck.py "+url + " > spf_result"
	# with open(os.devnull,'w') as devnull:
	subprocess.call(cmd,shell=True)	
	print(colored("[+] SPF Validation Check Completed","yellow"))


def masscaning(IP):
	print(colored("[+] Started Port Scanning on 65535 Ports[masscan]","green"))
	cmd = f"masscan {IP} -p 0-65535 --rate 3000 -oG masscan_results"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd,shell=True,stdout=devnull,stderr=devnull)
	print(colored("[+] Port Scanning Completed","yellow"))

def nmap(IP):
	print(colored("[+] Started Port Scanning on 65535 Ports[masscan]","green"))
#	cut_cmd = f"""cat masscan_results | grep "/"|awk -F" " '{print $5}'| cut -d "/" -f1 | awk -F "\n" 'ORS="," {print $1}'"""
	ports = (subprocess.check_output(cut_cmd,shell=True)),decode() 
	nmap_cmd= f"nmap -sV {IP} -p {ports}"

def check_subtakeover():
	print(colored("[+] Testing For Subdomain Takeover(subjack)","green"))
	cmd = f"subjack -w subdomains.txt -o SubHijack_result"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd,shell=True)
	print(colored("[+] Subdomain Takeover Testing Completed","yellow"))

	###ADD SUBOVER ALSO >>>>COPY PROVIDERS>JSON IN CURRENT DIRECTORY

def hakrawler(cookie):
	print(colored("[+] Crawling For Links [hakrawler]","green"))
	if cookie:
		cmd_hakrawler = f"cat subdomains.txt | hakrawler -plain -cookie {cookie} depth 1 > temp_hakrawler_output.txt"
	else:
		cmd_hakrawler = "cat subdomains.txt | hakrawler -plain -depth 3 > temp_hakrawler_output.txt"

	subprocess.call(cmd_hakrawler,shell=True)
	subprocess.call("sort -u temp_hakrawler_output.txt > hakrawler_output.txt",shell=True)  #Could have used python filter domain but this works lot faster
	os.remove("temp_hakrawler_output.txt")
	print(colored("[+] Web Crawling Completed","yellow"))


def extract_js():
	print(colored("[+] Extracting Javascript Links [subjs]","green"))
	cmd_extractJS = "cat hakrawler_output.txt | subjs | sort -u > subjs_result.txt"
	subprocess.call(cmd_extractJS,shell=True)

	print(colored("[+] Downloading Javascript files [aria2c]","green"))
	cmd_downloadJS = "aria2c -c -x 10 -d js_files -i subjs_result.txt"
	subprocess.call(cmd_downloadJS,shell=True,stdout=DEVNULL,stderr=DEVNULL)
	print(colored("[+] Javascript Files Download Completed","yellow"))


def gfauto():

	print(colored("[+] Started Grep-Finder [gf]","green"))

	os.mkdir("gf_results")
	os.chdir("js_files")

	gf_list=((subprocess.check_output("gf --list",shell=True)).decode()).split("\n")
	all_files = os.listdir()

	for file in all_files:       #Removing Directories
		if os.path.isdir(file):
			all_files.remove(file)

	try:
		remove_patterns = ["","ip","sec","jsvar","php-errors","servers","upload-fields","urls","meg-headers","http-auth","debug-pages","fw","php-sinks","json-sec","s3-buckets","urls"]
		for item in remove_patterns:
			gf_list.remove(item)
	except:
		pass

	pattern_with_one_process = ["ip","sec","jsvar","php-errors","servers","upload-fields","urls","meg-headers","http-auth","debug-pages","fw","php-sinks","json-sec","s3-buckets","urls"]   ###Patterns that display result from all file by default

	for pattern in pattern_with_one_process:
		with open("../gf_results/summary.txt","a") as summary_file:
			with open(f"../gf_results/{pattern}","a") as result_file:

				# print(colored(pattern,"yellow")+"  --> "+colored("*","cyan"),end="\r"),
				# sys.stdout.flush()
				cmd = f"cat * | gf {pattern}"
				output = (subprocess.check_output(cmd,shell=True)).decode()
				
				if len(output)>1:
					# print(colored(pattern,"yellow")+"  --> "+colored("*","cyan")+"                                                                 ")
					summary_file.write(f"{pattern}  --> Check {pattern} File\n")
					result_file.write(output)

					with open("../gf_results/logs.txt","a") as logFile:
						logFile.write(f"{pattern} = Check {pattern} File\n")


	##For other Patterns
	for pattern in gf_list:
		total_found = 0

		with open("../gf_results/summary.txt","a") as summary_file:
			with open(f"../gf_results/{pattern}","a") as result_file:
				for file in all_files:
					# print(colored(pattern,"yellow")+"  --> "+colored(file,"cyan"),end="\r"),
					# sys.stdout.flush()

					cmd = f"cat {file} | gf {pattern}"
					output = (subprocess.check_output(cmd,shell=True)).decode()
					if len(output)>1:
						total_found +=1
						# print(colored(pattern,"yellow")+"  --> "+colored(file,"cyan")+"                                                                 ")
						summary_file.write(f"{pattern}  --> {file}\n")
						result_file.write(f"FILE007: {file}\n{output}\n---------------------------------------------------------------\n")

				if total_found==0:
					os.remove(f"../gf_results/{pattern}")
				else:
					with open("../gf_results/logs.txt","a") as logFile:
						logFile.write(f"{pattern} = {total_found}\n")

	print("                                                                                                            ")

	print(colored("[+] Grep-Finder Completed","yellow"))



#dig @8.8.8.8









def main():
	banner()
	
#ARGS
	if os.geteuid() != 0:
		exit(colored("[-] Please run the program as sudo","red"))

	url = get_args().url
	if "http" in url:
		print(colored("Enter URL in format example.tld","red","red")) 
		exit(1)

	start_phase = get_args().start_phase or 1
	run_amass = get_args().amass or False
	gau_single=get_args().gau_single or False
	cookie = get_args().cookie or None
	
	if get_args().output:
		if os.path.exists(output):
			os.chdir(output)
		else:
			print(colored("Output Directory Not found","red"))
			exit()

###
	configParser = configparser.RawConfigParser()
	configFilePath = "/opt/killer_py_programs/recon-007/config.txt"   #SEE THIS FILE PATH
	configParser.read(configFilePath)

	SHODAN_API = configParser.get('KEYS', 'shodanAPI')
	GITTOKEN = configParser.get('KEYS', 'githubAPI')
###

	signal.signal(signal.SIGINT, signal_handler)

	print(colored("[+] Resolving IP: ","green"),end="")
	try:	
		ip = socket.gethostbyname(url)
	except:
		ip = "Could Not Detect"

	print(colored(ip,"magenta"))

	if ip=="Could Not Detect":
		ip = input(colored("[?] Enter IP Manually[Leave Empty to ignore masscan,vhostdsicovery]: ","cyan"))
	
	if start_phase==1:
		create_unique_directory(url)	

##VHOST
	if start_phase==1 or start_phase==4:
		vhost_ans = input(colored("[?] Scan for Virtual Hosts?(y/n): ","green"))   #ln -s /pathTovhostdiscovey/scan.rb  /usr/local/bin/virtual-host-discovery.rb

		if vhost_ans=="" or vhost_ans.lower()=='y' or vhost_ans.lower()=='yes':
			host = input (colored(f"[?] Enter the Host Name ({url}): ","green"))
			if host=="":
				host=url

		if len(GITTOKEN) > 0:
			GAS_ans = input(colored("[?] Run Git-All-Secrets? (y/n): ","green")) 
			if GAS_ans=="" or GAS_ans.lower()=='y' or GAS_ans.lower()=='yes':
				org = input(colored("[?] Enter Organiztion to scan: ","green"))

	if start_phase==1:
		print(colored("\n---------------------------------------------------------\n\t\t\tPHASE 1\n---------------------------------------------------------","blue"))
		t_sublister = threading.Thread(target=sublister,name="Thread_sublister",args=([url]))
		t_sublister.start()
		t_assetfinder = threading.Thread(target=assetfinder,name="Thread_assetfinder",args=([url]))
		t_assetfinder.start()
		t_subfinder= threading.Thread(target=subfinder,name="Thread_subfinder",args=([url]))
		t_subfinder.start()
		if run_amass==True:
			t_amass = threading.Thread(target=amass,name="Thread_amass",args=([url]))
			t_amass.start()

		if len(SHODAN_API) > 0:
			t_shosubgo = threading.Thread(target=shosubgo,name="Thread_shosubgo",args=([url],[SHODAN_API]))
			t_shosubgo.start()

		if len(GITTOKEN) > 0:
			t_githubSubs = threading.Thread(target=github_subdomains,name="Thread_github_subdomains",args=([url],[GITTOKEN]))
			t_githubSubs.start()

		t_sublister.join()
		t_assetfinder.join()
		t_subfinder.join()
		if run_amass==True:
			t_amass.join()

		if len(SHODAN_API) > 0:
			t_shosubgo.join()
		if len(GITTOKEN) > 0:
			t_githubSubs.join()

		t_filterSubs = threading.Thread(target=filter_subs,name="Thread_Filter_subs")
		t_filterSubs.start()
		t_filterSubs.join()

#BATCH2 
	if start_phase==1 or start_phase==2:
		print(colored("\n---------------------------------------------------------\n\t\t\tPHASE 2\n---------------------------------------------------------","blue"))


		t_httpProbe = threading.Thread(target=http_probe,name="Thread_HttpProbe")
		t_httpProbe.start()

		t_getallurls  = threading.Thread(target=getallURLs,name="Thread_getAllURls",args=([url],[gau_single]))
		t_getallurls.start()

		t_waybackrobots  = threading.Thread(target=waybackrobots,name="Thread_Waybackrobots",args=([url]))
		t_waybackrobots.start()

		t_httpProbe.join()
		t_getallurls.join()

	if start_phase==1 or start_phase==2 or start_phase==3:

		print(colored("\n---------------------------------------------------------\n\t\t\tPHASE 3\n---------------------------------------------------------","blue"))


		t_hakrawler = threading.Thread(target=hakrawler,name="Thread_hakrawler",args=([cookie]))
		t_hakrawler.start()

		t_subTakeover = threading.Thread(target=check_subtakeover,name="Thread_SubHijack")
		t_subTakeover.start()
		t_subTakeover.join()

		t_ParamUrls = threading.Thread(target=get_url_with_param,name="url_with_param")
		t_ParamUrls.start()
		t_ParamUrls.join()

		t_UniqUrls = threading.Thread(target=get_urls_with_uniq_params,name="url_with_param")
		t_UniqUrls.start()
		t_UniqUrls.join()

		t_urls_with_http = threading.Thread(target=get_urls_with_http,name="urls_with_http")
		t_urls_with_http.start()
		t_urls_with_http.join()

		t_hakrawler.join()

	if start_phase==1 or start_phase==2 or start_phase==3 or start_phase==4:
		print(colored("\n---------------------------------------------------------\n\t\t\tPHASE 4\n---------------------------------------------------------","blue"))

		t_WAF = threading.Thread(target=WAF_fingerprint,name="Thread_WAF",args=([url]))
		t_WAF.start()

		t_SPF = threading.Thread(target=spf_validate,name="Thread_SPF_Validate",args=([url]))
		t_SPF.start()

		if vhost_ans=="" or vhost_ans.lower()=='y' or vhost_ans.lower()=='yes':
			t_vhostDiscovery = threading.Thread(target=virtual_host_discovery,name='Thread_vhostDiscover',args=([ip,host]))
			t_vhostDiscovery.start()

		if len(GITTOKEN) > 0 and GAS_ans=="" or GAS_ans.lower()=='y' or GAS_ans.lower()=='yes':
			t_gitAllSecrets = threading.Thread(target=git_all_secrets,name='Thread_gitAllSecrets',args=([GITTOKEN],[org]))
			t_gitAllSecrets.start()
			t_gitAllSecrets.join()
					
		if vhost_ans=="" or vhost_ans.lower()=='y' or vhost_ans.lower()=='yes':
			t_vhostDiscovery.join()

		t_WAF.join()
		t_SPF.join()

	if start_phase==1 or start_phase==2 or start_phase==3 or start_phase==4 or start_phase==5:
		print(colored("\n---------------------------------------------------------\n\t\t\tPHASE 5\n---------------------------------------------------------","blue"))

		if ip != "":
			t_masscan = threading.Thread(target=masscaning,name="masscan",args=([ip]))
			t_masscan.start()

		t_aquatone = threading.Thread(target=aquatone,name="Thread_Aquatone")
		t_aquatone.start()

		t_extractJS = threading.Thread(target=extract_js,name="Thread_extractJS")
		t_extractJS.start()

		t_extractJS.join()
		t_aquatone.join()
	#	t_waybackrobots.join() must be there in phase 4

		if ip != "":
			t_masscan.join()
	
	if start_phase==1 or start_phase==2 or start_phase==3 or start_phase==4 or start_phase==5 or start_phase==6:
		print(colored("\n[X]-----------------PHASE6----------------[X]","blue"))

		t_gf = threading.Thread(target=gfauto,name="Thread_gfauto")
		t_gf.start()
		t_gf.join()

	print(colored("\nOutputs Saved To","cyan")+colored(os.getcwd(),"cyan"))
	print(colored("\n[+] Recon Finished [+] ","yellow"))

main()

