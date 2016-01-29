# If FAIL_OPEN is set to True, then authentication will succeed when
# communication with DuoAPI fails.
FAIL_OPEN=True
# User cache allows for caching the authentication validation for USER_CACHE_TIME
# time. This means authentication will succeed and DuoAPI auth() will be bypassed
# for USER_CACHE_TIME after the first successfull authentication.
# Use 0 to disable.
USER_CACHE_TIME=60*60*24
USER_CACHE_PATH="/var/tmp/vpn_user_cache.pickle"

# Log settings
# USE_SYSLOG only make sense when not using USE_LEGACY_CEF as CEF is always sent over syslog anyway
USE_LEGACY_CEF=False
USE_SYSLOG=True
USE_MOZDEF=True
#Path to your CA or CA bundle. This is particularly important on older deployments where python-requests may use an
# outdated CA database
CA_PATH=/etc/ssl/cert.pem

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
# Only users with this attribute can log in at all
LDAP_MUST_ATTR_VALUE=""
LDAP_MUST_ATTR=""
# Users this attr value will BYPASS duo auth.
LDAP_NO_DUOSEC_ATTR_VALUE=""
LDAP_DUOSEC_ATTR=""
