#!/usr/bin/env python2
# vim: set noexpandtab:ts=4

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Contributors: gdestuynder@mozilla.com

import duo_client
import time
import socket
import sys
import os
import traceback
import syslog
import cPickle as pickle

# If FAIL_OPEN is set to True, then authentication will succeed when
# communication with DuoAPI fails.
FAIL_OPEN=True
# User cache allows for caching the authentication validation for USER_CACHE_TIME
# time. This means authentication will succeed and DuoAPI auth() will be bypassed
# for USER_CACHE_TIME after the first successfull authentication.
# Use 0 to disable.
USER_CACHE_TIME=60*60*24
USER_CACHE_PATH="/var/tmp/vpn_user_cache.pickle"
USE_CEF_LOG=True
USERNAME_HACK=True

if os.path.isfile(USER_CACHE_PATH):
	user_cache = pickle.load(open(USER_CACHE_PATH, "rb"))
else:
	user_cache = {}

def fail_open():
	return FAIL_OPEN

def init():
	ikey = os.environ.get('ikey')
	skey = os.environ.get('skey')
	host = os.environ.get('host')
	username = os.environ.get('common_name')
	client_ipaddr = os.environ.get('ipaddr', '0.0.0.0')
	factor = os.environ.get('password', 'auto')
	passcode=None
	if factor not in ['push', 'sms', 'phone', 'auto']:
		if factor.startswith('passcode:'):
			passcode = factor.split(':')[1]
			factor = 'passcode'
		else:
			factor = 'auto'

	auth_api = duo_client.Auth(
		ikey=ikey,
		skey=skey,
		host=host,
	)
	return auth_api, username, client_ipaddr, factor, passcode

def log(msg):
	if USE_CEF_LOG:
		msg = cef(msg)
	syslog.openlog('duo_openvpn', 0, syslog.LOG_DAEMON)
	syslog.syslog(syslog.LOG_INFO, msg)
	syslog.closelog()

def cef(title="DuoAPI", msg="", ext=""):
	hostname = socket.gethostname()
	cefmsg = 'CEF:{v}|{deviceVendor}|{deviceProduct}|{deviceVersion}|{signatureID}|{name}|{message}|{deviceSeverity}|{extension}'.format(
					v='0',
					deviceVendor='Mozilla',
					deviceProduct='OpenVPN',
					deviceVersion='1.0',
					signatureID='0',
					name=title,
					message=msg,
					deviceSeverity='5',
					extension=ext+' dhost=' + hostname,
				)
	return cefmsg

def is_auth_cached(username, client_ipaddr):
	global user_cache
	now = time.time()
	if user_cache.has_key(username):
		try:
			tleft = user_cache[username]['timestamp']
			ipaddr = user_cache[username]['ipaddr']
		except:
			return False
		if client_ipaddr == ipaddr and tleft > now:
			return True
		del user_cache[username]
	return False

def add_auth_cache(username, client_ipaddr):
	global user_cache
	now = time.time()
	user_cache[username] = {'timestamp': now+USER_CACHE_TIME, 'ipaddr': client_ipaddr}
	pickle.dump(user_cache, open(USER_CACHE_PATH, "wb"))

def main():
	def ping():
		now = time.time()
		if not auth_api.ping():
			log('DuoAPI not responding')
		end = time.time()-now
		log('DuoAPI responded in %s seconds' % end)

	def check():
		if not auth_api.check():
			log('DuoAPI IKEY, SKEY or HOST are invalid')

	def clean_username(username):
		# use first part of email if an email is present
		if (username.find('@') != -1):
			username = username.split('@')[0]
		return username

	def preauth(username):
		res = auth_api.preauth(username)
		return res['result']

	def doauth(username, factor, client_ipaddr, passcode):
		hostname = socket.gethostname()
		res = auth_api.auth(username=username, factor=factor, ipaddr=client_ipaddr,
							type="OpenVPN login", pushinfo="From%20server="+hostname, device="auto", passcode=passcode)
		return res

	auth_api, username, client_ipaddr, factor, passcode = init()

	if USERNAME_HACK:
		username = clean_username(username)

	try:
		ping()
		check()
		auth = preauth(username)
	except socket.error, s:
		log('DuoAPI contact failed %s' % (s))
		return fail_open()
	
	if auth == "allow":
		return True
	elif auth == "enroll":
		log('User %s needs to enroll first' % username)
		return False
	elif auth == "auth":
		log('User %s is known - authenticating' % username)

		# Auth bypass for cached usernames
		if is_auth_cached(username, client_ipaddr):
			log('User %s cached authentication success' % username)
			return True

		try:
			res = doauth(username, factor, client_ipaddr, passcode)
		except socket.error, s:
			log('DuoAPI contact failed %s' % (s))
			return fail_open()

		if res['result'] == 'allow':
			log('User %s is now authenticated with DuoAPI using %s' % (username, factor))
			add_auth_cache(username, client_ipaddr)
			return True

		log('User %s authentication failed: %s' % (username, res['status_msg']))
		return False
	else:
		log('User %s is not allowed to authenticate' % username)
		return False

if __name__ == "__main__":
	if main():
		sys.exit(0)
	sys.exit(1)
