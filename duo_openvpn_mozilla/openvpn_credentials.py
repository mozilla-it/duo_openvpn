"""
    This library is for gathering up the environmental variables that
    are presented to auth-user-pass-verify, and turning them into an
    object that represents the user's credentials, for use in sending
    off to our Duo client for validation.
"""
# vim: set noexpandtab:ts=4

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Contributors: gdestuynder@mozilla.com
import sys
import os
sys.dont_write_bytecode = True


class OpenVPNCredentials(object):
    # pylint: disable=too-few-public-methods
    """
        This class consists of the parsed-out credentials passed in by
        openvpn.  If we have garbage-in, __init__ will return early and
        is_valid will be false.  It would help to check
        https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
        in its 'Environmental Variables' section.

        We end up with a class object that has attributes:
        username = certificate-verified user name
        factor = their duo-magic-word second factor
        password = their plaintext password, if applicable
        client_ipaddr = their source IP, for reporting purposes
        passcode = their passcode, if they provided one
        valid = True/False (True if we have a valid environment)

        This is a somewhat simple class, but it does a LOT of preflight
        checks on the data for sanity.
    """

    DUO_RESERVED_WORDS = set(['auto', 'push', 'sms', 'phone'])
    # Cite: https://duo.com/docs/authapi#/auth
    # These are the reserved words that are 'factor's by which Duo
    # can solicit you for auth passcodes.  We strip out 'passcode'
    # because that factor is not Duo-specific.  It's you providing
    # a passcode via some app.

    def __init__(self):
        """
            This class takes the environmental variables that OpenVPN sets,
            after munges them into an object with user credentials we can use.
        """
        self.username = None
        self.password = None
        self.client_ipaddr = None
        self.factor = None
        self.passcode = None
        # We're invalid until we load variables
        self.valid = False

    def load_variables_from_environment(self):
        """
            We raise if there's a horrific/no-environment-set state,
            because that means we're criminally broken.
            else we set .valid and let 'is_valid()' tell of our failure.
        """
        # the environmental variable 'common_name' is what's attached to the
        # certificate of the user.  The cert's common_name is trusted.
        __common_name = os.environ.get('common_name')
        if __common_name is None or __common_name == '':
            # If we don't have this, it's game over. we're not going to trust
            # what the user sent in via the username prompt.
            raise ValueError('Must provide a common_name environment variable')

        # Grab their IP.  If they didn't provide one, put a fake in there
        # just to have something.
        __client_ipaddr = os.environ.get('untrusted_ip',
                                         'no-untrusted_ip-provided')

        # the environmental variable 'username' is provided by the user
        # it cannot be trusted for authentication.
        # We're going to call it the unsafe username, just to be clear.
        __unsafe_username = os.environ.get('username')

        # the environmental variable 'password' is what they typed in/sent.
        __password = os.environ.get('password')

        if ((__unsafe_username is None or __unsafe_username == '') and
                (__password is None or __password == '')):
            # We didn't get user-or-password.  This is not strictly fatal
            # in a single-factor world, but we're bombing out early because
            # a real client ought to be providing some info to us in our
            # MFA world (exempted clients never get here), and we're going
            # to fail them later anyway because there's no credentials to
            # validate.
            #
            # Pedantic note, the error message here is 'user/pass' - we
            # only NEED one of them, technically, but it's nice to have both.
            raise ValueError('Must provide user/pass credentials')

        if __password is None or __password == '':
            # Based on changes dating back to 2015, as an aid to
            # user-experience, we allow using username-as-password.
            # Useful if you paste a pw in your login, to login faster.
            # Apparently some clients don't let you only save your login
            # and re-enter the "password" every time.
            #
            # This stems back from
            # https://github.com/mozilla-it/duo_openvpn/pull/8
            # h/t emorley
            if ((__unsafe_username is not None) and
                    (self.is_a_passcode(__unsafe_username) or
                     __unsafe_username in self.__class__.DUO_RESERVED_WORDS)):
                # If the 'username' that someone entered is a passcode
                # then we do some gymnastics to sort the variables out.
                __password = __unsafe_username
                __unsafe_username = ''
            else:
                # NOTE! We are into a code path that essentially springs
                # from a one-off user PR.  We're into a terminal else
                # clause because I can't think of what else would be
                # a valid answer here.  There might be a case where the
                # other valid password/passcode methods are interesting,
                # but nobody has asked for them, so, for code simplicity
                # we're not doing that.
                #
                # We have no passcode/password sent in.  Give up.
                #
                # Pedantic note, the error message is that we didn't
                # have a password, which is true.  That we couldn't
                # save them is the true issue in this branch, but it all
                # points back to the user not filling out user/pass correctly.
                raise ValueError('No password/passcode was sent')

        # CAUTION: We ass-u-me that nobody has a real password that is
        # among the Duo reserved words.  If they do, well... that's going
        # to be sad for them and impossible to diagnose, but this should
        # never happen in this day and age of complex passwords.
        if __password in self.__class__.DUO_RESERVED_WORDS:
            # Their 'password' was one of the Duo reserved words.
            # Cite: https://duo.com/docs/authapi#/auth
            # We can't accept bareword 'passcode' because, well,
            # they would have to send a passcode.  XXXXXX code, and literal
            # 'passcode:XXXXXX' is accepted in the ELSE below.
            #
            # Set their 2nd factor to be what they asked for...
            __factor = __password
            # ... set passcode to None, since they didn't provide one
            __passcode = None
            # ... and null out 'their password'.
            __password = None
        else:
            # Handle various forms of passcodes, but also possibly
            # a non-MFA user's password.
            if self.is_a_passcode(__password):
                # They typed in a passcode of 6-8 digits, which is the
                # practical sizing of TOTP passcodes.  We don't trust
                # that this is correct, but it's close enough to give
                # them a try.
                #
                # set their 2nd factor to be literal 'passcode'...
                __factor = 'passcode'
                # ... capture their passcode ...
                __passcode = __password
                # ... and null out 'their password'.
                __password = None
            elif __password.startswith('passcode:'):
                # They explicitly say this is a passcode, which is probably
                # because it's not all digits.  This is something we've
                # included as a safety valve for a world of non-numeric
                # passcodes.  As such, we deliberately do not check
                # is_a_passcode in this section.
                # This means we could have junk passcodes make it
                # through.  Good luck!
                # Set their 2nd factor to be literal 'passcode'...
                __factor = 'passcode'
                # ... capture their passcode ...
                __passcode = __password.split(':', 1)[1]
                # ... and null out 'their password'.
                __password = None
            elif __password.find(':') != -1:
                # This goes back to the age-old convention of sending in
                # password:RSAcode.
                __tmplist = __password.split(':')
                __tmp = __tmplist.pop()
                if self.is_a_passcode(__tmp):
                    __factor = 'passcode'
                    __passcode = __tmp
                    __password = ':'.join(__tmplist)
                else:
                    # This is some password : not a passcode.
                    # It's possible you could get here because passcodes'
                    # structure has changed, but overall this is a "dead
                    # end."  At best, we're a password for a 1FA user.
                    __factor = None
                    __passcode = None
            else:
                # We have failed to find usable credentials.
                # At best, we're a password for a 1FA user.
                __factor = None
                __passcode = None

        self.username = __common_name
        self.password = __password
        self.client_ipaddr = __client_ipaddr
        self.factor = __factor
        self.passcode = __passcode
        self.valid = True

    @staticmethod
    def is_a_passcode(input_string):
        """ return True if a string looks like a TOTP/HOTP passcode """
        # This is a best guess at a passcode's structure.
        # https://tools.ietf.org/html/rfc6238#appendix-A
        # The reference implementation of DIGITS_POWER suggests that codes
        # 1-8 are in spec.  In reality, 6 is a common thing, 8 is occasional.
        # This function could need to be changed if there are longer codes.
        # But absent a spec with better info, we're coding in 6-8.
        return (input_string.isdigit() and
                (len(input_string) == 6 or
                 len(input_string) == 7 or
                 len(input_string) == 8))

    def is_valid(self):
        """ If our config validation failed, this will go False """
        return self.valid
