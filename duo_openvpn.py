#!/usr/bin/env python2
# vim: set noexpandtab:ts=4

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Contributors: gdestuynder@mozilla.com

import sys
import imp
import os

cfg_path = ['duo_openvpn.conf', '/etc/openvpn/duo_openvpn.conf', '/etc/duo_openvpn.conf']
config = None

for cfg in cfg_path:
	if os.path.isfile(cfg):
		try:
			config = imp.load_source('config', cfg)
		except:
			pass

if config == None:
	print("Failed to load config")
	sys.exit(1)

sys.path.append('duo_client')

import duo_client
import time
import socket
import traceback
import syslog
import cPickle as pickle
if config.LDAP_CONTROL_BIND_DN:
	import ldap
if config.USE_MOZDEF:
	import mozdef

def log(msg):
	if not config.USE_LEGACY_CEF:
		mozmsg = mozdef.MozDefMsg(config.MOZDEF_URL, tags=['openvpn', 'duosecurity'])
		if config.USE_SYSLOG:
			mozmsg.sendToSyslog = True
		if not config.USE_MOZDEF:
			mozmsg.syslogOnly = True
		mozmsg.send(msg)
	else:
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

def ldap_get_dn(username):
	dn = ldap_attr_get(config.LDAP_URL, config.LDAP_CONTROL_BIND_DN, config.LDAP_CONTROL_PASSWORD, config.LDAP_BASE_DN, 'mail='+username, 'dn', True)
	return dn

def ldap_attr_get(url, binddn, password, basedn, value_filter, attr, attr_key=False):
	conn = ldap.initialize(url)
	try:
		conn.bind_s(binddn, password)
	except ldap.LDAPError, e:
		conn.unbind_s()
		log('LDAP bind failed' % e)
		return None

	try:
		res = conn.search_s(basedn, ldap.SCOPE_SUBTREE, value_filter, [attr])
		#list of attributes
		if attr_key:
			return res[0][0]
		else:
			return res[0][1][attr]
	except:
		log('ldap_attr_get() filter search failed for %s=>%s (returning key? %s)' % (value_filter, attr, attr_key))
		return None

def ldap_auth(username, user_dn, password):
	if (username == None) or (password == None) or (user_dn == None):
		log('User %s LDAP authentication failed' % username)
		return False

	conn = ldap.initialize(config.LDAP_URL)
	try:
		conn.bind_s(user_dn, password)
		conn.unbind_s()
		log('User %s successfully authenticated against LDAP' % username)
		return True
	except ldap.LDAPError:
		conn.unbind_s()
	log('User %s LDAP authentication failed' % username)
	return False

class DuoAPIAuth:
	def __init__(self, ikey, skey, host, username, client_ipaddr, factor, passcode, username_hack, failmode, cache_path, cache_time):
		self.failmode = failmode
		self.passcode = passcode
		if username_hack:
			self.username = self.clean_username(username)
		else:
			self.username = username
		self.client_ipaddr = client_ipaddr
		self.hostname = socket.gethostname()
		self.username = username
		self.client_ipaddr = client_ipaddr
		self.factor = factor
		self.user_cache_time = cache_time

		self.auth_api = duo_client.Auth(
			ikey=ikey,
			skey=skey,
			host=host)

		if os.path.isfile(cache_path):
			self.cache_path = cache_path
			self.user_cache = pickle.load(open(cache_path, "rb"))
		else:
			self.cache_path = None
			self.user_cache = {}

	def fail_open(self):
		return self.failmode

	def is_auth_cached(self):
		now = time.time()
		if self.user_cache.has_key(self.username):
			try:
				tleft = self.user_cache[self.username]['timestamp']
				ipaddr = self.user_cache[self.username]['ipaddr']
			except:
				return False
			if self.client_ipaddr == ipaddr and tleft > now:
				return True
			del self.user_cache[self.username]
		return False

	def add_auth_cache(self):
		# No IP? No cache for you.
		if self.client_ipaddr == '0.0.0.0':
			return
		if self.cache_path == None:
			return
		now = time.time()
		self.user_cache[self.username] = {'timestamp': now+self.user_cache_time, 'ipaddr': self.client_ipaddr}
		pickle.dump(self.user_cache, open(self.cache_path, "wb"))

	def ping(self):
		now = time.time()
		if not self.auth_api.ping():
			log('DuoAPI not responding')
		end = time.time()-now
		log('DuoAPI responded in %s seconds' % end)

	def check(self):
		if not self.auth_api.check():
			log('DuoAPI IKEY, SKEY or HOST are invalid')

	def clean_username(self, username):
		# use first part of email if an email is present
		try:
			if (username.find('@') != -1):
				username = username.split('@')[0]
		except:
			log('Failed to clean_username()')
			return username
		return username

	def preauth(self):
		res = self.auth_api.preauth(self.username)
		return res['result']

	def doauth(self):
		if self.passcode:
			res = self.auth_api.auth(username=self.username, factor=self.factor, ipaddr=self.client_ipaddr,
								passcode=self.passcode)
		else:
			res = self.auth_api.auth(username=self.username, factor=self.factor, ipaddr=self.client_ipaddr,
								type="OpenVPN login", pushinfo="From%20server="+self.hostname, device="auto")
		return res

	def auth(self):
		try:
			self.ping()
			self.check()
			auth = self.preauth()
		except socket.error, s:
			log('DuoAPI contact failed %s' % (s))
			return self.fail_open()

		if auth == "allow":
			return True
		elif auth == "enroll":
			log('User %s needs to enroll first' % self.username)
			return False
		elif auth == "auth":
			log('User %s is known - authenticating' % self.username)

			# Auth bypass for cached usernames
			if self.is_auth_cached():
				log('User %s cached authentication success' % self.username)
				return True

			try:
				res = self.doauth()
			except socket.error, s:
				log('DuoAPI contact failed %s' % (s))
				return self.fail_open()

			if res['result'] == 'allow':
				log('User %s is now authenticated with DuoAPI using %s' % (self.username, self.factor))
				self.add_auth_cache()
				return True

			log('User %s authentication failed: %s' % (self.username, res['status_msg']))
			return False
		else:
			log('User %s is not allowed to authenticate' % self.username)
			return False

def main():
	username_trusted = True
	username = os.environ.get('common_name')
	if (username == None):
# take username as provided by the user - it cannot be trusted
		username = os.environ.get('username')
		username_trusted = False
	client_ipaddr = os.environ.get('untrusted_ip', '0.0.0.0')
	password = os.environ.get('password', 'auto')
	passcode = None
	factor = None

# Nope? then nope.
	if username == None or username == '' or password == None or password == '':
		log("User %s (%s) Missing username or password, (reported username may be None due to this)" % (username,
			client_ipaddr))
		return False

# If you don't have a password, your username is your password (For ex you might be pasting an OTP as username. That's
# totally ok!
	if (len(username) == 0 and username.isdigit()):
		password = username

# If your real password is push/sms/phone/auto then you don't deserve to use this anyway :P
	if password not in ['push', 'sms', 'phone', 'auto']:
		if (password.isdigit() and len(password) == 6 or len(password) == 8):
			passcode = password
			factor = 'passcode'
		elif password.startswith('passcode:'):
			passcode = password.split(':')[1]
			factor = 'passcode'
		elif password.find(':') != -1:
			tmp = password.split(':')[1]
			if (tmp.isdigit() and len(tmp) == 6 or len(tmp) == 8):
				passcode=tmp
				factor = 'passcode'
				password = password.split(':')[0]
		else:
			factor = None
	else:
		factor = password
		password = None

	try:
		user_dn = ldap_get_dn(username)
	except:
		traceback.print_exc()
		log('User %s (%s) authentication failed, because ldap_get_db() failed to get user full LDAP dn' % (username, client_ipaddr))
		return False

	if config.LDAP_CONTROL_BIND_DN != '':
# User in an authorized group to use the VPN at all?
		if config.LDAP_MUST_ATTR != '':
			try:
				groups = ldap_attr_get(config.LDAP_URL, config.LDAP_CONTROL_BIND_DN,
										config.LDAP_CONTROL_PASSWORD, config.LDAP_CONTROL_BASE_DN,
										config.LDAP_MUST_ATTR_VALUE, config.LDAP_MUST_ATTR)
			except:
				traceback.print_exc()
				log('User %s (%s) authentication failed, because ldap_attr_get() failed to get user group attributes' % (username, client_ipaddr))
				return False

			if (user_dn not in groups):
				log('Authentication failed: rejecting user %s (%s) - not part of the allowed group attributes' % (username, client_ipaddr))
				return False

# DO NOT USE DuoSec for users with LDAP_NO_DUOSEC_ATTR_VALUE in LDAP_DUOSEC_ATTR
		try:
			uid = ldap_attr_get(config.LDAP_URL, config.LDAP_CONTROL_BIND_DN,
								config.LDAP_CONTROL_PASSWORD, config.LDAP_BASE_DN,
								'mail='+username, 'uid')[0]
			groups = ldap_attr_get(config.LDAP_URL, config.LDAP_CONTROL_BIND_DN,
									config.LDAP_CONTROL_PASSWORD, config.LDAP_CONTROL_BASE_DN,
									config.LDAP_NO_DUOSEC_ATTR_VALUE, config.LDAP_DUOSEC_ATTR)
		except:
			traceback.print_exc()
			log('User %s (%s) authentication failed, because ldap_attr_get() failed to get user uid or group attributes' % (username, client_ipaddr))
			return False

		try:
			if (uid in groups) or (username in groups) or (user_dn in groups):
				log('Bypassing DuoSec authentication for user %s - using LDAP only instead (whitelisted)')
				return ldap_auth(username, user_dn, password)
		except:
			traceback.print_exc()
			log('User %s (%s) authentication failed, because ldap_auth() failed unexpectedly' % (username, client_ipaddr))
			return False

		if config.TRY_LDAP_ONLY_AUTH_FIRST and password != None:
# If this works, we bail here
			if ldap_auth(username, user_dn, password):
				return True

	try:
		if factor != None and username_trusted:
			duo = DuoAPIAuth(config.IKEY, config.SKEY, config.HOST, username, client_ipaddr, factor,
							passcode, config.USERNAME_HACK, config.FAIL_OPEN, config.USER_CACHE_PATH, config.USER_CACHE_TIME)
			return duo.auth()
	except:
		log('User %s (%s) authentication failed, because DuoAPIAuth() failed unexpectedly' % (username, client_ipaddr))
		traceback.print_exc()
		return False

	log('User %s authentication failed (no trusted username/common_name with Duo push?)' % username)
	return False

if __name__ == "__main__":
	control = os.environ.get('auth_control_file')
	if control == None:
		log('No control file found, if using a deferred plugin authentication will stall and fail.')

	if main():
		try:
			with open(control, 'w') as f:
				f.write('1')
		except:
			pass
		sys.exit(0)

	try:
		with open(control, 'w') as f:
			f.write('0')
	except:
		pass
	sys.exit(1)
