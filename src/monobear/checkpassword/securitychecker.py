#!/usr/bin/env python3
import logging
import hashlib
import re
import json
import datetime
import pprint
import redis
import requests
from password_strength import PasswordStats
from email.message import EmailMessage
import smtplib
import ssl

class SecurityChecker(object):

    def __init__(self, redisHost, redisPort, redisPwd=''):
        self._redisHost = redisHost
        self._redisPort = redisPort
        self._redisPwd = redisPwd
        self._redis = None
        self._log = logging.getLogger(__name__)
        self._connectRedis()

    def _checkTroyHunt(self, pwd):
        pwdSha1 = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
        r = requests.get('https://api.pwnedpasswords.com/range/{:s}'.format(pwdSha1[:5]))
        if r.status_code != 200:
            return False
        else:
            hashes = r.text.split('\r\n')
            for x in hashes:
                if x.split(':')[0] == pwdSha1[5:]:
                    return True
            return False

    def _connectRedis(self):
        # connect to redis.
        self._redis = redis.Redis(
            host=self._redisHost,
            port=self._redisPort,
            password=self._redisPwd
        )
        if self._redis is None:
            self._log.error('Can\'t connect to redis via {}:{}'.format(self._redisHost, self._redisPort))
        return self._redis is not None

    def checkPasswordSecurity(self, mailaddr, password):
        """
        Verify the strength of 'password'
        Returns a dict indicating the wrong criteria
        A password is considered strong if:
            8 characters length or more
            1 digit or more
            1 symbol or more
            1 uppercase letter or more
            1 lowercase letter or more
        Taken from https://stackoverflow.com/questions/16709638/checking-the-strength-of-a-password-how-to-check-conditions#32542964
        """

        # calculating the length
        length_error = len(password) < 8

        # searching for digits
        digit_error = re.search(r"\d", password) is None

        # searching for uppercase
        uppercase_error = re.search(r"[A-ZÄÖÜ]", password) is None

        # searching for lowercase
        lowercase_error = re.search(r"[a-zäöüß]", password) is None

        # searching for symbols
        symbol_error = re.search(r"\W", password) is None

        # check if password consists of only lowercase + digits at end.
        password_digit_error = re.search(r"^[a-zäöüß]+\d+$", password) is not None

        # troy hunt check!
        troyhunt_error = self._checkTroyHunt(password)

        # check additional information depending on account availability
        name_error = False
        mailacct = mailaddr.split('@', 1)[0].lower()
        try:
            first, last = mailacct.split('.', 1)
        except ValueError:
            first = mailacct
            last = None
        if (first and len(first) > 3 and first in password.lower()) or \
           (last and len(last) > 3 and last in password.lower()):
            name_error = True

        # calculate entropy
        stats = PasswordStats(password)

        # different levels of errors
        noncritical_error = [digit_error, uppercase_error, lowercase_error, symbol_error, name_error]
        critical_error = [password_digit_error, troyhunt_error, length_error]

        # overall result
        password_ok = not(
            noncritical_error.count(True) > 1 or
            critical_error.count(True) > 0
        )

        return {
            'password_ok' : password_ok,
            'length_error' : length_error,
            'digit_error' : digit_error,
            'uppercase_error' : uppercase_error,
            'lowercase_error' : lowercase_error,
            'symbol_error' : symbol_error,
            'password_digit_error': password_digit_error,
            'name_error': name_error,
            'troyhunt': troyhunt_error,
            'entropy': stats.strength(),
            'category_noncritical': noncritical_error.count(True) > 1,
            'category_critical': critical_error.count(True) > 0
        }

    def checkPassword(self, mailaddr, pwd):
        pwdSha1 = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
        keyName = 'monobear/pwd/' + hashlib.md5((mailaddr + pwd + pwdSha1).encode('utf-8')).hexdigest() + ':5'
        newResult = True
        try:
            checkResult = self._redis.get(keyName)
        except AttributeError:
            pass
        else:
            if checkResult:
                checkResult = json.loads(checkResult.decode('utf-8'))
                newResult = False

        if not checkResult:
            checkResult = self.checkPasswordSecurity(mailaddr, pwd)
            # mark password as checked
            try:
                self._redis.set(keyName, json.dumps(checkResult))
            except Exception as e:
                self._log.warning('Don\'t cache password check result, as redis not available ({}).'.format(str(e)))
            else:
                ttl = datetime.timedelta(weeks=1).total_seconds()
                self._redis.expire(keyName, int(ttl))

        if checkResult['troyhunt']:
            self._log.debug('Password for user {mail} is at troyhunt {result}.'.format(
                mail=mailaddr, result=pprint.pformat(checkResult)
            ))
            return False, '* OK [ALERT] Your password is insecure and was leaked. Please change your password soon.', \
                   newResult, checkResult
        elif checkResult['category_critical']:
            self._log.debug('Password for user {mail} is not fine {result}.'.format(
                mail=mailaddr, result=pprint.pformat(checkResult)
            ))
            return False, '* OK [ALERT] Your password is insecure. Please consider to change it.', \
                   newResult, checkResult
        else:
            self._log.debug('Password for user {mail} is fine.'.format(mail=mailaddr))
            return True, '', newResult, checkResult

    def informUser(self, mailacct, errMsg, result, smtpConfig):
        msg = EmailMessage()
        tpl = """Dear Sir or Madam, \r\n\r\n
You recently logged into your mail account {mail}. \r\n
We would like to inform you, that your account is not proper secure, as 
your password is weak ({msg}). See details below: \r\n
{checkresult}
\r\n
Kindly check and change your password.\r\n
Best regards,
Your provider."""
        msg.set_content(tpl.format(mail=mailacct, msg=errMsg, checkresult=pprint.pformat(result)))
        msg['Subject'] = 'Insecure account {mail}'.format(mail=mailacct)
        msg['From'] = smtpConfig.get('sender')
        msg['To'] = mailacct
        msg['Date'] = datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')

        # Send the message via our own SMTP server.
        with smtplib.SMTP(host=smtpConfig.get('host'), port=int(smtpConfig.get('port', 587))) as s:
            if bool(smtpConfig.get('tls', False)):
                sctx = ssl.create_default_context()
                if not bool(smtpConfig.get('verifyCert', True)):
                    sctx.check_hostname = False
                    sctx.verify_mode = ssl.CERT_NONE
                s.starttls(context=sctx)
            s.send_message(msg)
