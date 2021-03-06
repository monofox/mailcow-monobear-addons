from .securitychecker import SecurityChecker
import argparse
import yaml

if __name__ == '__main__':
    import os, logging, sys
    log = logging.getLogger(__name__)
    parser = argparse.ArgumentParser(description='Check password security')
    parser.add_argument('--config', '-c', type=str, help='Configuration file', required=True)
    args = parser.parse_args()

    config = {
        'redis': {
            'host': '127.0.0.1',
            'port': 6379,
            'pwd': ''
        },
        'smtp': {
            'notify': False
        }
    }
    try:
        with open(args.config, 'rb') as f:
            config = yaml.safe_load(f.read())
    except FileNotFoundError as e:
        log.error('Can\'t load and parse config file: ({})'.format(str(e)))

    try:
        user = os.environ['USER']
        pwd = os.environ['PLAIN_PASS']
    except KeyError:
        log.error('Don\'t checking password security as no $USER / $PLAIN_PASS given in environment.')
    else:
        redis = config.get('redis', None)
        if redis:
            s = SecurityChecker(redis.get('host'), redis.get('port'), redis.get('pwd'))
            rStatus, rMessage, newResult, checkResult = s.checkPassword(user, pwd)
            if not rStatus:
                sys.stdout.write(rMessage + '\r\n')
                if newResult and bool(config.get('smtp').get('notify', False)):
                    s.informUser(user, rMessage, checkResult, config.get('smtp'))
