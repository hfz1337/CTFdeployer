#!/usr/bin/python3
from termcolor import colored
import argparse
import requests as req
import re
import json
import os

url = 'http://localhost:8000'                                # The CTFd platform base URL
cookies = {'session':'259a720c-bbb3-4eb1-b76b-8cca58e013de'} #fac1f8b6-7ef1-4d77-abcb-110936c49ab1'} # The CTFd admin session cookie

def get_parser():
	parser = argparse.ArgumentParser(description='                    [Hafidh ZOUAHI | gh_zouahi@esi.dz]\n'
	'  ____ _____ _____   _            _                         _           _   \n'
	' / ___|_   _|  ___|_| | ___ _ __ | | ___  _   _  ___ _ __  | |__   ___ | |_ \n'
    '| |     | | | |_ / _` |/ _ \ \'_ \| |/ _ \| | | |/ _ \ \'__| | \'_ \ / _ \| __|\n'
	'| |___  | | |  _| (_| |  __/ |_) | | (_) | |_| |  __/ |    | |_) | (_) | |_ \n'
    ' \____| |_| |_|  \__,_|\___| .__/|_|\___/ \__, |\___|_|    |_.__/ \___/ \__|\n'
	'                           |_|            |___/                             \n\n'
	'In order to deploy challenges:\n'
	'   [!] Each challenge must be in a separate folder containing the following elements:\n'
	'       name.txt           The file that contains the name of the challenge\n'
	'       category.txt       The file that contains the name of the category that the challenge belongs to\n'
	'       description.txt    The file that contains the description of the challenge\n'
	'       value.txt          The file that contains the number of points earned by solving the challenge\n'
	'       state.txt          The file that contains the state of the challenge, either hidden or visible\n'
	'       type.txt           The file that contains the type of the challenge, either standard or dynamic\n'
	'       flag.txt           The file that contains the flag of the challenge\n'
	'       files/             The folder that contains the files associated to the challenge\n'
	'   [!] All challenges folders must be in the same root directory.\n'
	'   [!] Then the script should be used as follow: ./CTFdeployer -a path/to/root/dir',
	formatter_class = argparse.RawTextHelpFormatter)
	group = parser.add_mutually_exclusive_group(required=False)
	group.add_argument(
        "-a",
        metavar="directory",
        dest="directory",
        help="Root directory of the challenges.",
    )
	group.add_argument(
        "-d",
        metavar="id",
        dest="d_id_list",
		help="Delete one or more challenges. For example, to delete\n"
		"challenges from id=5 to id=10 (inclusive), use -d5-10.\n"
		"To delete challenges whose id=5 and id=10, use -d5,10.",
	)
	group.add_argument(
        "-c",
        metavar="id",
        dest="c_id_list",
        help="Change the state of one or more challenges, the same\n"
        "way -d is used.",
    )
    
	return parser

def print_green(s):
    print(colored(s, 'green'))

def print_red(s):
    print(colored(s, 'red'))
    
def get_csrf_nonce(response):
	return re.search('csrf_nonce = "[a-z0-9]{64}"', response.text).group(0)[-65:-1]

def delete(ch_id):
    csrf_nonce = get_csrf_nonce(req.get(url = url + '/admin/challenges/' + ch_id, cookies = cookies))
    headers = {'csrf-token': csrf_nonce, 'content-type': 'application/json'}
    resp = req.delete(url = url + '/api/v1/challenges/' + ch_id, cookies = cookies, headers = headers)
    if resp.ok: print_green('[+] Challenge n°' + ch_id + ' successfully deleted!')
    else: print_red('[-] There was an error deleting challenge n°' + ch_id)

def change_state(ch_id):
	states = {'visible':'hidden', 'hidden':'visible'}
	csrf_nonce = get_csrf_nonce(req.get(url = url + '/admin/challenges/' + ch_id, cookies = cookies))
	headers = {'csrf-token':csrf_nonce, 'content-type': 'application/json'}
	resp = req.get(url = url + '/api/v1/challenges/' + ch_id, cookies = cookies, headers = headers)
	data = json.loads(resp.text.strip())['data']
	state = states[data['state']]
	ch_info = {"name":data['name'],
               "category":data['category'],
               "description":data['description'],
               "value":data['value'],
               "state":state,
               "type":data['type']}
	resp = req.patch(url = url + '/api/v1/challenges/' + ch_id, cookies = cookies, json = ch_info, headers = headers)
	if resp.ok: print_green('[+] Challenge n°' + ch_id + '\'s state is now: ' + state)
	else: print_red('[-] There was an error changing challenge n°' + ch_id + '\'s state.')
    
def deploy_chall(data, files2up):
	print_green('[+] Deploying challenge: ')
	print_green('    Name        => ' + data['ch_info']['name'])
	print_green('    Category    => ' + data['ch_info']['category'])
	print_green('    Description => ' + data['ch_info']['description'])
	print_green('    Value       => ' + data['ch_info']['value'])
	print_green('    State       => ' + data['ch_info']['state'])
	print_green('    Type        => ' + data['ch_info']['type'])
	print_green('    Files       => ' + str(len(data['files'])))
	# Creating the challenge
	csrf_nonce = get_csrf_nonce(req.get(url = url + '/admin/challenges/new', cookies = cookies))
	headers = {'csrf-token': csrf_nonce, 'content-type': 'application/json'}
	resp = req.post(url = url + '/api/v1/challenges', cookies = cookies, json = data['ch_info'], headers = headers)
	# Recovering challenge's id
	data['ch_id'] = json.loads(resp.text.strip())['data']['id']
	# Sending flag
	data['flag_info']['challenge'] = str(data['ch_id'])
	csrf_nonce = get_csrf_nonce(req.get(url = url + '/admin/challenges/' + str(data['ch_id']), cookies = cookies))
	headers = {'csrf-token': csrf_nonce, 'content-type': 'application/json'}
	resp = req.post(url = url + '/api/v1/flags', cookies = cookies, json = data['flag_info'], headers = headers)
	if files2up:
		# Uploading challenge's files
		resp = req.get(url = url + '/admin/challenges/' + str(data['ch_id']), cookies = cookies)
		data['files'].append(('nonce', ('', get_csrf_nonce(resp))))
		data['files'].append(('challenge', ('', data['ch_id'])))
		data['files'].append(('type', ('', 'challenge')))
		resp = req.post(url = url + '/api/v1/files', cookies = cookies, files = data['files'])
	print_green('[+] Challenge successfully deployed!')
	
	
def load_chall_info(directory):
	data = {'ch_info':{}}
	files2up = False
	if 'files' in os.listdir(directory):
		if os.listdir(directory + '/files') != []: files2up = True
	for i in ['name', 'category', 'description', 'value', 'state', 'type']:
		data['ch_info'][i] = open(directory + '/' + i + '.txt').read().strip()
	data['flag_info'] = {"content":open(directory + '/flag.txt').read().strip(),
                         "type":"static"}
	data['files'] = []
	if files2up:
		for i in os.listdir(directory + '/' + 'files'):
			data['files'].append(('file', open(directory + '/files/' + i, 'rb')))
			
	return data, files2up

def main():
	parser = get_parser()
	args = parser.parse_args()
	if args.directory:
		directory = args.directory
		if directory[-1] != '/': directory += '/'
		challs = os.listdir(directory)
		for i in challs:
			a, b = load_chall_info(directory + i)
			deploy_chall(a, b)
		
	elif args.d_id_list:
		if '-' in args.d_id_list:
			a, b = args.d_id_list.split('-')
			a, b = int(a), int(b)
			for i in range(a, b+1):
				delete(str(i))
				
		elif ',' in args.d_id_list:
			l = args.d_id_list.split(',')
			for i in l:
				delete(i)
		else:
			delete(args.d_id_list)
	elif args.c_id_list:
		if '-' in args.c_id_list:
			a, b = args.c_id_list.split('-')
			a, b = int(a), int(b)
			for i in range(a, b+1):
				change_state(str(i))
				
		elif ',' in args.c_id_list:
			l = args.c_id_list.split(',')
			for i in l:
				change_state(args.c_id_list)
		else:
			change_state(str(i))
	else:
		parser.print_help()

if __name__ == '__main__':
	main()
