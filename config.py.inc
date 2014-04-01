# If FAIL_OPEN is set to True, then authentication will succeed when
# communication with DuoAPI fails.
FAIL_OPEN=True
# User cache allows for caching the authentication validation for USER_CACHE_TIME
# time. This means authentication will succeed and DuoAPI auth() will be bypassed
# for USER_CACHE_TIME after the first successfull authentication.
# Use 0 to disable.
USER_CACHE_TIME=60*60*24
USER_CACHE_PATH="/var/tmp/vpn_user_cache.pickle"
#cef, none, or mozdef
LOG_METHOD='mozdef'
MOZDEF_LOGGER='https://127.0.0.1:8080/events'
USERNAME_HACK=True

# Duo settings
IKEY=''
SKEY=''
HOST=''

# LDAP settings
# Auth/login
TRY_LDAP_ONLY_AUTH_FIRST=False
LDAP_URL="ldap://"
LDAP_BASE_DN=''

LDAP_CONTROL_BIND_DN=""
LDAP_CONTROL_PASSWORD=""
LDAP_CONTROL_BASE_DN=""
# Only this attr value can log
LDAP_DUOSEC_ATTR_VALUE=""
LDAP_DUOSEC_ATTR=""
