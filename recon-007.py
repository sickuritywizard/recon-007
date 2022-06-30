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
import shutil,datetime


'''
PREREQUISITES
1) Add Shebangs to programs that don't have it + give it executable permission
2) Add the programs to env path so that it can be executed from anywhere
'''


def banner(url=""):
	x="""


	__________                                     _______  ________________ 
	\\______   \\ ____   ____  ____   ____           \\   _  \\ \\   _  \\______  \\
	 |       _// __ \\_/ ___\\/  _ \\ /    \\   ______ /  /_\\  \\/  /_\\  \\  /    /
	 |    |   \\  ___/\\  \\__(  <_> )   |  \\ /_____/ \\  \\_/   \\  \\_/   \\/    / 
	 |____|_  /\\___  >\\___  >____/|___|  /          \\_____  /\\_____  /____/  
			\\/     \\/     \\/           \\/                 \\/       \\/        
	  """


 
	y = "	+---------------------------------------------------------------------+"     
	z = "								     ~KILLER007\n"
	xurl =  "URL   : "+url
	xtime = "Time  : "+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	print(colored(x,'blue'))
	print(colored(y,'red'))
	print(colored(z,'green'))
	if not url=="":
		print(colored(xtime,'red'))
		print(colored(xurl+"\n\n",'red'))



def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-u','--url',dest='url',help="Specify URL")
	parser.add_argument('-c','--cookie',dest='cookie',help="Use Cookies[value=param;]")
	parser.add_argument('-o','--output',dest='output',help="Output Location")
	parser.add_argument('-d','--hak-depth',dest='hak_depth',help="Depth For hakrawler",default=3)
	parser.add_argument('-p','--phase',dest='start_phase',type=int,help="Start The Program from a Specific Phase")
	parser.add_argument('-g','--gau-single',dest='gau_single',action='store_true',help="Run gau on the main domain only")
	parser.add_argument('-a','--amass',dest='amass', action='store_true',help="Include Amass Scan")
	parser.add_argument('-mr','--mass-rate',dest='masscan_rate',type=int,help="Masscan Rate Flag (Default=3000)",default=3000)
	parser.add_argument('-k','--keep',dest='keep_individual_files',action='store_true',help="Keep each Subdomain tool result separtely ")
	parser.add_argument('--loose-scope',dest='loose_scope',action='store_true',help="Run Recon for related target aquistions also")
	parser.add_argument('-x','--print-phase',dest='printPhase',action='store_true',help="Print All Tasks in each Phases")


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

def print_Phases():
	phase1 = """
--------------------------------------
		PHASE-1
--------------------------------------
[x] Sublister\n[X] AssetFinder\n[X] SubFinder\n[X] Amass (Optional)
[x] Shosubgo\n[X] Github_Subdomains\n[X] Filter Subdomains"""

	phase2 = """
--------------------------------------
		PHASE-2
--------------------------------------
[X] HttProbe\n[X] Gau\n[X] WayBackRobots"""

	phase3 = """
--------------------------------------
		PHASE-3
--------------------------------------
[X] Hakrawler\n[X] SubOver\n[X] SubJack\n[X] Parameter-URLs
[X] Unique Parameter-URLs\n[X] Interesting-URLs\n"""

	phase4 = """
--------------------------------------
		PHASE-4
--------------------------------------
[X] Waf00f\n[X] SpoofCheck(SPF)\n[X] Vhost-Discovery\n[X] Git-All-Secrets"""

	phase5 = """
--------------------------------------
		PHASE-5
--------------------------------------
[X] Masscan\n[X] Aquatone\n[X] SubJS\n[X] JS-Download"""

	phase6 = """
--------------------------------------
		PHASE-6
--------------------------------------
[X] gf-URL-Files\n[X] gf-All-Files
"""

	print(colored(phase1,"yellow"))
	print(colored(phase2,"red"))
	print(colored(phase3,"blue"))
	print(colored(phase4,"magenta"))
	print(colored(phase5,"green"))
	print(colored(phase6,"white"))

def filter_duplicate_domains(x):
  return list(dict.fromkeys(x))


def check_file_exist(fpath):  
	return os.path.isfile(fpath) and os.path.getsize(fpath) > 0


def sublister(url):
	print(colored("[+] Scanning For Subdomains with Sublist3r",'green'))
	cmd_sublister = f"sublist3r -d {url} -o subdomain_results/sublister_subs_file.txt"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_sublister,shell=True,stdout=devnull,stderr=devnull)

	print(colored("[+] Sublist3r Scanning Completed",'yellow'))


def assetfinder(url):
	print(colored("[+] Scanning For Subdomains with AssetFinder",'green'))
	cmd_asset = f"assetfinder {url} --subs-only > subdomain_results/assetfinder_subs_file.txt"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_asset,shell=True,stdout=devnull)
	
	print(colored("[+] AssetFinder Scanning Completed",'yellow'))


def amass(url):
	print(colored("[+] Scanning For Subdomains with Amass",'green'))
	cmd_amass = f"amass enum -d {url} -o subdomain_results/amass_subs_file.txt"
	with open(os.devnull,'w') as devnull:	
		subprocess.call(cmd_amass,shell=True,stdout=devnull,stderr=devnull)
	print(colored("[+] Amass Scanning Completed",'yellow'))


def subfinder(url): 
	print(colored("[+] Scanning For Subdomains with Subfinder",'green'))
	cmd_subfinder = f"subfinder -d {url} -o subdomain_results/subfinder_subs_file.txt"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_subfinder,shell=True,stdout=devnull,stderr=devnull)
	print(colored("[+] Subfinder Scanning Completed",'yellow'))


def github_subdomains(url,GITTOKEN):	
	print(colored("[+] Scanning For Subdomains with github-subdomains",'green'))
	cmd_github_subdomains = f"github-subdomains.py -t {GITTOKEN} -d {url} > subdomain_results/github_subs_file.txt"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_github_subdomains,shell=True,stderr=devnull)
	print(colored("[+] Github-subdomains Scanning Completed",'yellow'))


def shosubgo(url,SHODANAPI):
	print(colored("[+] Scanning For Subdomains with Shosubgo",'green'))
	cmd_shosubgo = f"shosubgo_linux -d {url} -s {SHODANAPI} > subdomain_results/shosubgo_subs_files.txt"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_shosubgo,shell=True,stderr=devnull)
	print(colored("[+] Shosubgo Scanning Completed",'yellow'))


def filter_subs(url):
		all_subs = []
		try:                                                             #try block coz sometimes sublister gives error which breaks the entire program
			with open ('sublister_subs_file.txt','r') as sublister_subs:
				for line in sublister_subs:
					all_subs.append(line)
		except:
			pass

		try:			
			with open ('subdomain_results/assetfinder_subs_file.txt','r') as assetfinder_subs:
				for line in assetfinder_subs:
					all_subs.append(line)
		except:
			pass

		try:			
			with open ('subdomain_results/amass_subs_file.txt','r') as amass_subs:
				for line in amass_subs:
					all_subs.append(line)
		except:
			pass

		try:			
			with open ('subdomain_results/subfinder_subs_file.txt','r') as subfinder_subs:
				for line in subfinder_subs:
					all_subs.append(line)
		except:
			pass

		try:			
			with open ('subdomain_results/subdomain_results/github_subs_file.txt','r') as github_subs:
				for line in github_subs:
					all_subs.append(line)
		except:
			pass

		try:			
			with open ('subdomain_results/shosubgo_subs_files.txt','r') as shosubgo_subs:
				for line in shosubgo_subs:
					all_subs.append(line)
		except:
			pass


		filtered = filter_duplicate_domains(all_subs)
		with open ('subdomain_results/subdomain_temp.txt','w') as all_subs_file:
			for line in filtered:
				all_subs_file.write(line)

		print(colored("[+] Removed Duplicate Domains",'yellow'))

		##Remove Out Of Scope Subdomains
		if not get_args().loose_scope:
			subprocess.call(f'cat subdomain_results/subdomain_temp.txt | grep {url} > subdomain_results/subdomains.txt',shell=True)
			os.remove("subdomain_results/subdomain_temp.txt")
		else:
			os.rename("subdomain_results/subdomain_temp.txt","subdomain_results/subdomains.txt")

	
		if not get_args().keep_individual_files:

			try:
				os.remove('subdomain_results/amass_subs_file.txt')
			except:
				pass

			try:
				os.remove('subdomain_results/assetfinder_subs_file.txt')
				os.remove('subdomain_results/subfinder_subs_file.txt')
				os.remove('subdomain_results/shosubgo_subs_files.txt')
				os.remove('subdomain_results/github_subs_file.txt')
				os.remove('subdomain_results/sublister_subs_file.txt')
			except:
				pass


def http_probe():
	file = "subdomain_results/httprobe_subdomains.txt"
	print(colored("[+] Started HttProbe on subdomains.txt","green"))
	cmd_httprobe = "cat subdomain_results/subdomains.txt | httprobe > " + file
	subprocess.call(cmd_httprobe,shell=True)
	print(colored("[+] Httprobe Completed",'yellow'))


def aquatone():
	print(colored("[+] Starting Aquatone[This may take some time] ","green"))
	global aquatone_finished
	aquatone_finished = False
	cmd_aquatone = "cat subdomain_results/httprobe_subdomains.txt | aquatone --out aquatone_results/"
	time_thread = threading.Thread(target=time_status,name='Thread_time',args=(["Aquatone",200])).start()	
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_aquatone,shell=True,stdout=devnull)
	aquatone_finished = True 	
	print(colored("[+] Aquatone Scan Completed","yellow"))


def waybackurls(url):
	print(colored("[+] Started Waybackurls ","green"))
	cmd_waybackurls = "waybackurls "+url + " > waybackurl_result.txt"
	subprocess.call(cmd_waybackurls,shell=True)	
	print(colored("[+] Waybackurls Scan Completed","yellow"))


def getallURLs(url,gau_single):
	os.mkdir("ALL_URLS")
	print(colored("[+] Started GetAllURLS(gau) [This may take some time]","green"))
	if gau_single:
		cmd_gau = f"gau {url} > ALL_URLS/gau_results.txt" 
	else:
		cmd_gau = f"cat subdomain_results/subdomains.txt | gau > ALL_URLS/gau_results.txt" 

	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_gau,shell=True,stderr=devnull)	
	print(colored("[+] GetallURLs Scan Completed","yellow"))


def get_url_with_param():

	print(colored("[+] Filtering URLs with Parameters","green"))
	with open("ALL_URLS/gau_results.txt","r") as subfile:
		with open("ALL_URLS/urls_with_parameters.txt","w") as paramfile:
			for line in subfile:
				if "?" and "=" in line:
					paramfile.write(line)
	print(colored("[+] Filtered URLs with Parameters","yellow"))

def get_urls_with_uniq_params():  

	param_wordlist =[]   		#For Parameter Wordlist 
	unique_params=[]     		#List Used For Filtering Purpose
	urls_with_unique_params =[] #List to Store All Unique URLS

	with open("ALL_URLS/urls_with_parameters.txt","r") as file:
		for url in file:
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
		

	with open("ALL_URLS/urls_with_unique_params.txt","w") as file:
		for item in urls_with_unique_params:
			file.write(item)

	with open("ALL_URLS/parameter_wordlist.txt","w") as file:
		for item in param_wordlist:
			file.write(item+"\n")

	print(colored("[+] Created Wordlist of Parameters","yellow"))
	print(colored("[+] Filtered URLs Containing Unique Parameters","yellow"))



def get_juicy_files_n_params():
	juicy_files_n_params_cmd = "grep -iE 'xmlrpc|resetpass' ALL_URLS/gau_results.txt > ALL_URLS/juicy_files_n_params.txt"
	subprocess.call(juicy_files_n_params_cmd,shell=True)

	juicy_extension_cmd = "grep -iE '\.config|\.php|\.asp|\.jsp' ALL_URLS/gau_results.txt > ALL_URLS/juicy_extensions.txt"
	subprocess.call(juicy_extension_cmd,shell=True)

	urls_with_http_in_params_cmd = '''cut -b 1-4 --complement ALL_URLS/urls_with_unique_params.txt | grep "http" | awk -F="" '{print "http"$0}' > ALL_URLS/http_in_params.txt'''
	subprocess.call(urls_with_http_in_params_cmd,shell=True)


def waybackrobots(url):
	print(colored("[+] Started Waybackrobots","green"))
	cmd_waybackrobots = "waybackrobots "+url
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_waybackrobots,shell=True,stdout=devnull,stderr=devnull)
	print(colored("[+] Waybackrobots Scan Completed","yellow"))
	

def WAF_fingerprint(url):
	url = "https://www."+url
	print(colored("[+] Stated Firewall Fingerprinting[wafw00f]","green"))
	cmd_waf00f = f"wafw00f {url} -o wafw00f_results"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_waf00f,shell=True,stdout=devnull,stderr=devnull)	
	print(colored("[+] Firewall Fingerprinting(wafw00f) Completed","yellow"))	

def virtual_host_discovery(ip,host,wordlist):
	print(colored("[+] Started Virtual-Host-Discovery","green"))
	cmd_vhostDiscovery = f"virtual-host-discovery.rb --ip={ip} --host={host} --wordlist={wordlist} --output=vhost_results.txt"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_vhostDiscovery,shell=True,stdout=devnull,stderr=devnull)	
	print(colored("[+] Virtual-Host-Discovery Scan Completed","yellow"))

def git_all_secrets(gitToken,org):
	print(colored("[+] Started Git-All-Secrets","green"))
	# subprocess.call("sudo systemctl start docker",shell=True)	
	cmd_git_all_secrets = f"sudo docker run -it abhartiya/tools_gitallsecrets -token={gitToken} -org={org} > gitallsecrets.txt"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_git_all_secrets,shell=True,stdout=devnull)	
	subprocess.call("sudo systemctl stop docker",shell=True)	
	print(colored("[+] Git-All-Secretss Scan Completed","yellow"))

def spf_validate(url):
	print(colored("[+] Started SPF Validation","green"))
	cmd_spf_validate = "spoofcheck.py "+url + " > spf_result"
	# with open(os.devnull,'w') as devnull:
	subprocess.call(cmd_spf_validate,shell=True)	
	print(colored("[+] SPF Validation Check Completed","yellow"))


def masscaning(IP,rate):
	print(colored("[+] Started Port Scanning on 65535 Ports[masscan]","green"))
	cmd_masscan = f"sudo masscan {IP} -p 0-65535 --rate {rate} -oG masscan_results"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_masscan,shell=True,stdout=devnull,stderr=devnull)
	print(colored("[+] Port Scanning Completed","yellow"))

def nmap(IP):
	print(colored("[+] Started Port Scanning on 65535 Ports[masscan]","green"))
#	cut_cmd = f"""cat masscan_results | grep "/"|awk -F" " '{print $5}'| cut -d "/" -f1 | awk -F "\n" 'ORS="," {print $1}'"""
	ports = (subprocess.check_output(cut_cmd,shell=True)),decode() 
	nmap_cmd= f"nmap -sV {IP} -p {ports}"

def check_subtakeover(providersjson):
	print(colored("[+] Testing For Subdomain Takeover(subjack)","green"))
	cmd_subjack = f"subjack -w subdomain_results/subdomains.txt -v -o SubTakeover_results.txt"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_subjack,shell=True,stdout=devnull,stderr=devnull)

	print(colored("[+] Testing For Subdomain Takeover(SubOver)","green"))
	shutil.copy2(providersjson,'.')
	cmd_subOver = f"SubOver -l subdomain_results/subdomains.txt -v >> SubTakeover_results.txt"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_subOver,shell=True,stdout=devnull,stderr=devnull)

	os.remove("providers.json")
	print(colored("[+] Subdomain Takeover Test Completed","yellow"))
	

def hakrawler(cookie,depth):
	print(colored("[+] Crawling For Links [hakrawler]","green"))
	if cookie:
		cmd_hakrawler = f"cat subdomain_results/httprobe_subdomains.txt | hakrawler -plain -cookie {cookie} depth {depth} > temp_hakrawler_output.txt"
	else:
		cmd_hakrawler = f"cat subdomain_results/httprobe_subdomains.txt | hakrawler -plain -depth {depth} > temp_hakrawler_output.txt"

	subprocess.call(cmd_hakrawler,shell=True)
	subprocess.call("sort -u temp_hakrawler_output.txt > hakrawler_output.txt",shell=True)  #Could have used python filter domain but this works lot faster
	os.remove("temp_hakrawler_output.txt")
	print(colored("[+] Web Crawling Completed","yellow"))


def extract_js():
	os.mkdir("js_html_files")
	print(colored("[+] Extracting Javascript Links [subjs]","green"))
	cmd_subjs = "cat hakrawler_output.txt | subjs | sort -u > subjs_result.txt"
	subprocess.call(cmd_subjs,shell=True)
	print(colored("[+] Extracting Javascript Links [subjs] Completed","yellow"))

	print(colored("[+] Downloading Javascript files [aria2c]","green"))
	cmd_downloadJS = "aria2c -c -x 10 -d js_html_files -i subjs_result.txt"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_downloadJS,shell=True,stdout=devnull,stderr=devnull)
	print(colored("[+] Javascript Files Download Completed","yellow"))

	print(colored("[+] Removing Duplicate Javascript Files [smashDupes-007]","green"))
	cmd_smashdupes = "smashDupes-007 -d js_html_files -s"
	with open(os.devnull,'w') as devnull:
		subprocess.call(cmd_smashdupes,shell=True,stdout=devnull)
	print(colored("[+] Removed Duplicate Javascript Files","yellow"))


def organize():
	try:
		source = 'aquatone_results/html/'
		desti = 'js_html_files/'
		files = os.listdir(source)
		for file in files:
			shutil.move(source+file, desti)
	except:
		pass

	os.mkdir("gf_results")

def gf_allfiles():
	print(colored("[+] Started GF-007 on JS and HTML Files","green"))
	os.mkdir("gf_results/ALL_Files")
	all_files = os.listdir("js_html_files/")

	for file in all_files:   #Removing Directories
		if os.path.isdir(file):
			all_files.remove(file)

	allfiles_patterns = ["aws-keys","base64","cors","debug-pages","firebase","fw","go-functions","http-auth","ip","json-sec","meg-headers","php-curl","php-errors","php-serialized","php-sinks","php-sources","s3-buckets","sec","servers","strings","takeovers","upload-fields","urls","jsvar"]

	for pattern in allfiles_patterns:
		try:
			total_found = 0

			with open("gf_results/ALL_Files/summary.txt","a") as summary_file:
				with open(f"gf_results/ALL_Files/{pattern}","a") as result_file:
					for file in all_files:
						cmd = f"gf {pattern} js_html_files/{file}"
						output = (subprocess.check_output(cmd,shell=True)).decode()
						if len(output)>1:
							total_found +=1
							result_file.write(output)
							summary_file.write(f"{pattern}  --> {file}\n")

					if total_found==0:
						os.remove(f"gf_results/ALL_Files/{pattern}")
					else:
						with open("gf_results/ALL_Files/logs.txt","a") as logFile:
							logFile.write(f"{pattern} = {total_found}\n")

		except TypeError:
			pass
		except UnicodeDecodeError:
			pass

	print(colored("[+] GF-007 on JS and HTML Files Completed","yellow"))

def gf_urlfiles():
	os.mkdir("gf_results/URL_Files")
	files = ["ALL_URLS/urls_with_unique_params.txt","hakrawler_output.txt"] #Add more URL files here if needed
	print(colored("[+] Started GF-007 on URL Files","green"))

	urlfile_patterns = ["debug_logic","idor","img-traversal","interestingEXT","interestingparams","lfi","rce","redirect","sqli","ssrf","ssti","xss","base64"]

	for pattern in urlfile_patterns:
		for file in files:
			try:
					cmd = f"gf {pattern} {file}"
					output = (subprocess.check_output(cmd,shell=True)).decode()
					if len(output)>1:
						with open(f"gf_results/URL_Files/{pattern}","a") as result_file:
							result_file.write(output)
						with open("gf_results/URL_Files/summary.txt","a") as summary_file:
							summary_file.write(f"{pattern}  --> {file}\n")

			except TypeError:
				pass
			except UnicodeDecodeError:
				pass

	print(colored("[+] GF-007 on URL Files Completed","yellow"))


def main():
	
#ARGS
	if get_args().printPhase:
		banner()
		print_Phases()
		exit(1)
	# if os.geteuid() != 0:
	# 	exit(colored("[-] Please run the program as sudo","red"))

	if not get_args().url:
		banner()
		exit(colored("[-] -u / --url is required. Use --help for additional info","red"))

	url = get_args().url
	if "http" in url:
		url = url.split("/",2)[2]
		# print(colored("[-]Enter URL in format example.tld","red")) 
		# exit(1)

	if url.endswith("/"):
		url = url[:-1]

	banner(url)
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
	temppath = os.path.realpath(__file__).split('/')[:-1]
	program_path = "/".join(temppath)
	configFilePath = program_path +"/db/profile.conf"
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
	if start_phase==1 or start_phase==2 or start_phase==3 or start_phase==4:
		vhost_ans = input(colored("[?] Scan for Virtual Hosts?(y/n): ","green"))   #ln -s /pathTovhostdiscovey/scan.rb  /usr/local/bin/virtual-host-discovery.rb

		if vhost_ans=="" or vhost_ans.lower()=='y' or vhost_ans.lower()=='yes':
			host = input (colored(f"[?] Enter the Host Name ({url}): ","green"))
			if host=="":
				host=url

		if len(GITTOKEN) > 0:
			GAS_ans = input(colored("[?] Run Git-All-Secrets? (y/n): ","green")) 
			if GAS_ans=="" or GAS_ans.lower()=='y' or GAS_ans.lower()=='yes':
				org = input(colored("[?] Enter Organiztion to scan: ","green"))
				print(colored("[+] Starting Docker","green"))
				subprocess.call("sudo systemctl start docker",shell=True)	


	if start_phase==1:
		print(colored("\n---------------------------------------------------------\n\t\t\tPHASE 1\n---------------------------------------------------------","blue"))
		os.mkdir("subdomain_results")
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
			t_shosubgo = threading.Thread(target=shosubgo,name="Thread_shosubgo",args=(url,SHODAN_API))
			t_shosubgo.start()

		if len(GITTOKEN) > 0:
			t_githubSubs = threading.Thread(target=github_subdomains,name="Thread_github_subdomains",args=(url,GITTOKEN))
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

		t_filterSubs = threading.Thread(target=filter_subs,name="Thread_Filter_subs",args=([url]))
		t_filterSubs.start()
		t_filterSubs.join()

#BATCH2 
	if start_phase==1 or start_phase==2:
		print(colored("\n---------------------------------------------------------\n\t\t\tPHASE 2\n---------------------------------------------------------","blue"))


		t_httpProbe = threading.Thread(target=http_probe,name="Thread_HttpProbe")
		t_httpProbe.start()

		t_getallurls  = threading.Thread(target=getallURLs,name="Thread_getAllURls",args=(url,gau_single))
		t_getallurls.start()

		t_waybackrobots  = threading.Thread(target=waybackrobots,name="Thread_Waybackrobots",args=([url]))
		t_waybackrobots.start()

		t_httpProbe.join()
		t_getallurls.join()

	if start_phase==1 or start_phase==2 or start_phase==3:

		print(colored("\n---------------------------------------------------------\n\t\t\tPHASE 3\n---------------------------------------------------------","blue"))
		hak_depth = get_args().hak_depth
		t_hakrawler = threading.Thread(target=hakrawler,name="Thread_hakrawler",args=(cookie,hak_depth))
		t_hakrawler.start()

		providersjson = program_path + '/db/providers.json'
		t_subTakeover = threading.Thread(target=check_subtakeover,name="Thread_SubHijack",args=([providersjson]))
		t_subTakeover.start()
		t_subTakeover.join()

		t_ParamUrls = threading.Thread(target=get_url_with_param,name="url_with_param")
		t_ParamUrls.start()
		t_ParamUrls.join()

		t_UniqUrls = threading.Thread(target=get_urls_with_uniq_params,name="url_with_param")
		t_UniqUrls.start()
		t_UniqUrls.join()

		t_get_juicy_files_n_params = threading.Thread(target=get_juicy_files_n_params,name="urls_with_http")
		t_get_juicy_files_n_params.start()
		t_get_juicy_files_n_params.join()

		t_hakrawler.join()

	if start_phase==1 or start_phase==2 or start_phase==3 or start_phase==4:
		print(colored("\n---------------------------------------------------------\n\t\t\tPHASE 4\n---------------------------------------------------------","blue"))

		t_WAF = threading.Thread(target=WAF_fingerprint,name="Thread_WAF",args=([url]))
		t_WAF.start()

		t_SPF = threading.Thread(target=spf_validate,name="Thread_SPF_Validate",args=([url]))
		t_SPF.start()

		if vhost_ans=="" or vhost_ans.lower()=='y' or vhost_ans.lower()=='yes':
			vhost_wordlist = program_path + "/db/vhost_wordlist"
			t_vhostDiscovery = threading.Thread(target=virtual_host_discovery,name='Thread_vhostDiscover',args=([ip,host,vhost_wordlist]))
			t_vhostDiscovery.start()

		if len(GITTOKEN) > 0 and GAS_ans=="" or GAS_ans.lower()=='y' or GAS_ans.lower()=='yes':
			t_gitAllSecrets = threading.Thread(target=git_all_secrets,name='Thread_gitAllSecrets',args=(GITTOKEN,org))
			t_gitAllSecrets.start()
			t_gitAllSecrets.join()
					
		if vhost_ans=="" or vhost_ans.lower()=='y' or vhost_ans.lower()=='yes':
			t_vhostDiscovery.join()

		t_WAF.join()
		t_SPF.join()

	if start_phase==1 or start_phase==2 or start_phase==3 or start_phase==4 or start_phase==5:
		print(colored("\n---------------------------------------------------------\n\t\t\tPHASE 5\n---------------------------------------------------------","blue"))

		masscan_rate = get_args().masscan_rate
		if ip != "":
			t_masscan = threading.Thread(target=masscaning,name="masscan",args=(ip,masscan_rate))
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

		organize()
		t_gfAllfiles = threading.Thread(target=gf_allfiles,name="t_gfAllfiles")
		t_gfAllfiles.start()

		t_gfUrlfiles = threading.Thread(target=gf_urlfiles,name="t_gfUrlfiles")
		t_gfUrlfiles.start()

		t_gfAllfiles.join()
		t_gfUrlfiles.join()

	print(colored("\nOutputs Saved To","cyan")+colored(os.getcwd(),"cyan"))
	print(colored("\n[+] Recon Finished [+] ","yellow"))

main()