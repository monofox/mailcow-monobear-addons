from .securitychecker import SecurityChecker

if __name__ == '__main__':
    import os, logging, sys
    log = logging.getLogger(__name__)
    try:
        user = os.environ['USER']
        pwd = os.environ['PLAIN_PASS']
    except KeyError:
        log.error('Don\'t checking password security as no $USER / $PLAIN_PASS given in environment.')
    else:
        s = SecurityChecker('127.0.0.1', 6379, '')
        rStatus, rMessage = s.checkPassword(user, pwd)
        if not rStatus:
            sys.stdout.write(rMessage + '\r\n')
