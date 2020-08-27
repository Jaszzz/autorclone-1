#!/usr/bin/python3

import os
import re
import sys
import json
import time
import glob
import psutil
import logging
import subprocess
import configparser
import argparse
import filelock
import signal
import shlex
import socket
import hashlib
import random
import psutil
import collections
import signal
import datetime
from contextlib import closing
from colorama import Back, Fore, Style
from pathlib import Path
from logging.handlers import RotatingFileHandler

def signal_handler(sig, frame):
    if sig == signal.SIGINT:
        logger.critical('Program interrupted by SIGINT.')
        log_cleanup()
        sys.exit()

def log_cleanup():
    logger.info('Cleaning up log file garbage.')
    logs = [instance_lock_path, instance_config_path, rclone_log_path, script_log_file]
    for log in logs:
       try:
           os.remove(log)
       except FileNotFoundError:
           pass

def generate_rclone_union_from_config(tdbasename):
    if not tdbasename:
        return false

    config = configparser.ConfigParser()
    config.read(rclone_config_path)

    td_collection = []
    td_index = 1
    while True:
        td_name = "{}_{}".format(tdbasename,td_index)
        try:
            td_config = config[td_name]
        except KeyError:
            break
        td_collection.append(td_name + ":")
        td_index = td_index + 1

    if len(td_collection) == 0:
        logger.critical('Can\'t find section %s in your rclone.conf', (tdbasename))
        exit(1)

    td_union_join = " ".join(td_collection)
    td_union_env = {}
    td_headers = {
        "rcb": "RCLONE_CONFIG",
        "tdname": tdbasename,
        "vars": [
            ("TYPE","union"),
            ("REMOTES", td_union_join)
        ]
    }
    for var in td_headers.get("vars"):
        td_env_key = "{rcb}_{tdname}_{varkey}".format(rcb=td_headers.get("rcb"), tdname=td_headers.get("tdname"), varkey=var[0])
        td_union_env[td_env_key] = "{varval}".format(varval=var[1])

    return td_union_env

def get_rclone_log_tail(f, n, offset=0):
    offset_total = str(n+offset)
    proc = subprocess.Popen(['tail', '-n', offset_total, f], stdout=subprocess.PIPE).communicate()[0]
    lines = proc.decode().split("\n")
    max_length,longest_element = max([(len(x),x) for x in lines])
    output = ['{}{}__{}{}{}{}{}\n'.format(
        Back.WHITE, Fore.BLACK, Style.RESET_ALL, Style.BRIGHT, Fore.WHITE, i, Style.RESET_ALL) for i in lines]

    section_title = "\n{}{}rclone output:{}\n".format(Back.WHITE,Fore.BLACK,Style.RESET_ALL)
    output.insert(0,section_title)

    if len(output) > 0:
        return "".join(output)
    else:
        return "No output available."

def is_sa_being_used(sa_file):
    try:

        sa_binary_sha256 = hashlib.sha256()

        with open(sa_file, 'rb') as saf:
            buf = saf.read()
            sa_binary_sha256.update(buf)

        instance_check = filelock.FileLock(sa_track_lock)
        with instance_check.acquire(timeout=0):
            with open(sa_track_log, "r") as f:
                for line in f:
                    if sa_binary_sha256.hexdigest() in line:
                        return True
            return False
    except:
        logger.info("Another instance holds the lock for the SA track log. Waiting 5 seconds...")
        time.sleep(5)
        is_sa_being_used(sa_file)

def update_track_log(sa_file, remove=False):
    try:
        instance_check = filelock.FileLock(sa_track_lock)
        with instance_check.acquire(timeout=0):

            sa_binary_sha256 = hashlib.sha256()

            with open(sa_file, 'rb') as saf:
                buf = saf.read()
                sa_binary_sha256.update(buf)

            with open(sa_track_log, "r", newline="") as f:
                lines = f.readlines()

            with open(sa_track_log, "w", newline="") as f:
                sa_binary_sha256_hex = sa_binary_sha256.hexdigest()
                sa_line_str = "{}\n".format(sa_binary_sha256_hex)
                for i,line in enumerate(lines,0):
                    if sa_binary_sha256_hex in line:
                        if not remove:
                             lines[i] = sa_line_str
                        else:
                             lines[i] = ""
                        break
                else: # not found, EOF
                    if not remove:
                        lines.append(sa_line_str) # append missing data

                f.writelines(lines) # rewrite all lines

            return True
    except:
        logger.info("Another instance holds the lock for the SA track log. Waiting 5 seconds...")
        time.sleep(5)
        update_track_log(sa_file)

def is_project_banned(sa_file):
    try:
        with open(sa_file) as saf:
            saf_data = json.load(saf)
            saf_project_id = saf_data['project_id']
            if saf_project_id in sa_project_temp_bans:
                return True
    except:
        logger.warning("Something happened when trying to read SA JSON file.")
        time.sleep(5)
        is_project_banned(sa_file)

def add_project_ban(sa_file):
    try:
        with open(sa_file) as saf:
            saf_data = json.load(saf)
            saf_project_id = saf_data['project_id']
            sa_project_temp_bans.append(saf_project_id)
            return True
    except:
        logger.warning("Something happened when trying to read SA JSON file.")
        time.sleep(5)
        add_project_banned(sa_file)


def is_sa_banned(sa_file):
    try:

        sa_binary_sha256 = hashlib.sha256()

        with open(sa_file, 'rb') as saf:
            buf = saf.read()
            sa_binary_sha256.update(buf)

        instance_check = filelock.FileLock(sa_ban_lock)
        with instance_check.acquire(timeout=0):

            with open(sa_ban_log, "r") as f:
                for line in f:
                    if sa_binary_sha256.hexdigest() in line:
                        sa_log_hex, sa_ban_log_unixtime = tuple(line.rstrip().split(" "))
                        if (int(time.time()) - int(sa_ban_log_unixtime)) < int(86400): # not at least 24 hours later
                            return True
            return False
    except:
        logger.info("Another instance holds the lock for the SA ban log. Waiting 5 seconds...")
        time.sleep(5)
        is_sa_banned(sa_file)

def update_ban_log(sa_file):
    try:
        instance_check = filelock.FileLock(sa_ban_lock)
        with instance_check.acquire(timeout=0):

            sa_ban_from_unixtime = int(time.time())
            sa_binary_sha256 = hashlib.sha256()

            with open(sa_file, 'rb') as saf:
                buf = saf.read()
                sa_binary_sha256.update(buf)

            with open(sa_ban_log, "r", newline="") as f:
                lines = f.readlines()

            with open(sa_ban_log, "w", newline="") as f:
                sa_binary_sha256_hex = sa_binary_sha256.hexdigest()
                sa_line_str = "{} {}\n".format(sa_binary_sha256_hex,sa_ban_from_unixtime)
                for i,line in enumerate(lines,0):
                    if sa_binary_sha256_hex in line:
                        lines[i] = sa_line_str
                        break
                else: # not found, EOF
                    lines.append(sa_line_str) # append missing data

                f.writelines(lines) # rewrite all lines

            return True
    except:
        logger.info("Another instance holds the lock for the SA ban log. Waiting 5 seconds...")
        time.sleep(5)
        update_ban_log(sa_file)


def get_listen_port(pid):
    bash_cmd = "ss -l -p -n -t"
    proc = subprocess.Popen(shlex.split(bash_cmd), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
    output = proc.communicate()[0]
    for line in output.split("\n"):
        if "pid={}".format(pid) in line:
            match = re.findall(r'([0-9]+(?:\.[0-9]+){3}):([0-9]+)', line)
            if match:
                return match[0][1]
            else:
                return None

def get_open_port():
    port = random.randrange(10000,65535)
    return port
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex(("127.0.0.1",port)) == 0:
            return port
        else:
            get_open_port()

def write_config(name, value):
    instance_config[name] = value
    with open(instance_config_path, 'w') as f:
        json.dump(instance_config, f, sort_keys=True)


# ?????Service Account Credentials JSON file path
def get_next_sa_json_path(_last_sa):

    # Give random SA not already used;
    # this method won't produce an IndexError
    # like the previous index-based method; But it also won't stop
    # the script if all SAs have errored
    next_sa = random.choice(sa_jsons)
    while next_sa == _last_sa:
        next_sa = random.choice(sa_jsons)
    return next_sa

    #
    #if _last_sa not in sa_jsons:
    #    next_sa_index = 0
    #else:
    # Initial SA picked; new random one.
    #    _last_sa_index = sa_jsons.index(_last_sa)
    #    next_sa_index = _last_sa_index + (1)
    # ???????????
    #if next_sa_index > len(sa_jsons):
    #    next_sa_index = next_sa_index - len(sa_jsons)
    #return sa_jsons[next_sa_index]


def switch_sa_by_config(cur_sa):
    # ??SA??
    logger.info('Change rclone.conf SA information to %s' % (cur_sa))
    rclone_remote_env_key = "RCLONE_CONFIG_{destname}_SERVICE_ACCOUNT_FILE".format(destname=rclone_dest_name)
    proc_env[rclone_remote_env_key] = "{varval}".format(varval=cur_sa)
    logger.info('Change SA information in rclone.conf Success')
    print(proc_env)

def get_email_from_sa(sa):
    logger.info('Reading SA: {}'.format(sa))
    return json.load(open(sa, 'r'))['client_email']

# ????Rclone
def force_kill_rclone_subproc(pid):
    if psutil.pid_exists(pid):
        proc = psutil.Process(pid)
        logger.info('Get the rclone process information - pid: %s, name: %s' % (pid, proc.name()))
        logger.info('Force killed rclone process which pid: %s' % proc.pid)
        proc.kill()

""" ---------------- Main Program Below ---------------- """

'''
5. Change logging and tracking into "with" operation to ensure SIGINT is handled correctly (eg. deleting/updating files)
6. User rate limit error detection causing premature TD switch; might use combination of zero transferred and user error
7. Randomize selection of service account JSON files; avoid projects temp banned.
8. Keep log of temp banned projects from ratelimit
'''

# ------------?????------------------

time_id = '{}'.format(int(time.time()))

# system and user
user_home = str(Path.home())

# ??rclone?? (s)
check_after_start = 30  # ???rclone???,??xxs??????rclone??,?? rclone rc core/stats ????
check_interval = 5  # ???????rclone rc core/stats?????

# rclone????????
td_switch_count = 0
sa_switch_count = 0
switch_level = 2  # ?????????,???????????,??????True(???)???,? 1 - 4(max)
rclone_switch_rules = {
    'up_than_750': False,  # ????????750G                      # May cause premature switch if actively transfering
    'error_user_rate_limit': True,  # Rclone ????rate limit?? # Might be triggered by warning instead of actual error
    'zero_transferred_between_check_interval': True,           # Doesn't work well with long queuing process
    'all_transfers_in_zero': False,  # ????transfers??size??0  # Activates immediately after running
    'error_td_file_limit': True,                               # Will also switch the SA with the TD
    'error_project_quota': False,                              # Will trigger even if server-side activity works, or if genuine low level retry
    'user_limit_and_zero_data': True
}

# ???????
instance_lock_path = '/tmp/autorclone_{}.lock'.format(time_id)
instance_config_path = '/tmp/autorclone_{}.conf'.format(time_id)

# ???????
script_log_file = '/tmp/autorclone_{}.log'.format(time_id)
logging_datefmt = "%m/%d/%Y %I:%M:%S %p"
logging_format = "%(asctime)s - %(levelname)s - %(funcName)s - %(message)s"

# rclone runtime configuration
rclone_bwlimit = "--bwlimit 4M" # not in use
rclone_log_path = "/tmp/rclone_{}.log".format(time_id)

# service account ban log
sa_ban_log = '{}/.autorclone/autoclone_ban_log.txt'.format(user_home)
sa_ban_lock = '/tmp/sa_ban_log.lock'.format(time_id)

# service account tracking
sa_track_log = '{}/.autorclone/autoclone_track_log.txt'.format(user_home)
sa_track_lock = '{}/.autorclone/autoclone_track_log.lock'.format(user_home)

# service account project temp ban log
sa_project_temp_bans = []

# proc vars
proc_env = os.environ.copy()

# ????
instance_config = {}
sa_jsons = []

# Initiate logger
logFormatter = logging.Formatter(fmt=logging_format, datefmt=logging_datefmt)
logger = logging.getLogger()
logger.setLevel(logging.NOTSET)
while logger.handlers:  # Remove un-format logging in Stream, or all of messages are appearing more than once.
    logger.handlers.pop()
if script_log_file:
    fileHandler = RotatingFileHandler(filename=script_log_file, mode='a', backupCount=2, maxBytes=5 * 1024 * 1024, encoding=None, delay=0)
    fileHandler.setFormatter(logFormatter)
    logger.addHandler(fileHandler)
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)

# Signal handler
signal.signal(signal.SIGINT, signal_handler)

parser = argparse.ArgumentParser(description="Process command line arguments for " + __file__)
parser.add_argument('--service-accounts-dir', type=str, default="/home/opsoyo/.config/autorclone/service_accounts", nargs='?', help='service account JSON directory')
parser.add_argument('--switch-by-config', action='store_true', help='make autorclone switch by config instead of runtime')
parser.add_argument('--sa-config-name', type=str, help='set rclone config section name for --switch-by-config; req.')
parser.add_argument('--rclone-bin', type=str, default="/usr/bin/rclone", nargs='?', help='rclone binary path')
parser.add_argument('--rclone-config', type=str, default="/home/opsoyo/.config/rclone/rclone.conf", nargs='?', help='rclone config path')
parser.add_argument('--rclone-exclude-exts', type=str, nargs='+', help='rclone extension exclude list')
parser.add_argument('--td-rotate-name', type=str, nargs='?', help='rotate the writable team drive on error')
parser.add_argument('--save-logs', action='store_true', help='save logs made by autorclone and rclone')
parser.add_argument('commands', type=str, metavar='cmd', nargs='+', help='rclone command string')

args = parser.parse_args()

# handle pair arguments
if args.switch_by_config and args.sa_config_name is None:
    parser.error("--switch-by-config requires --sa-config-name.")

sa_json_folder = args.service_accounts_dir
rclone_config_path = args.rclone_config
switch_sa_way = 'config' if args.switch_by_config else 'runtime'
rclone_dest_name = args.sa_config_name
td_rotate_name = args.td_rotate_name

# Make log directories and files as needed
Path(os.path.dirname(sa_ban_log)).mkdir(parents=True, exist_ok=True)
Path(sa_ban_log).touch()
Path(sa_track_log).touch()

# Time between user rate limit errors
userlimit_first_log_dtm = None

for command in args.commands:
    # Fill out rclone command from arg
    cmd_rclone = "{} {}".format(args.rclone_bin, command)

    # Run with lock on instance to make clean break
    instance_check = filelock.FileLock(instance_lock_path)
    with instance_check.acquire(timeout=0):

        break_for_next_cmd = False

        # ??account??
        sa_jsons = glob.glob(os.path.join(sa_json_folder, '*.json'))
        if len(sa_jsons) == 0:
            logger.error('No Service Account Credentials JSON file exists.')
            exit(1)

        # ??instance??
        if os.path.exists(instance_config_path):
            logger.info('Instance config exist, Load it...')
            config_raw = open(instance_config_path).read()
            instance_config = json.loads(config_raw)

        # ??????pid??????
        if 'last_pid' in instance_config:
            last_pid = instance_config.get('last_pid')
            logger.debug('Last PID exist, Start to check if it is still alive')
            force_kill_rclone_subproc(last_pid)

        # ??????sa??????,?????,??sa_jsons
        # ?????????????750G???
        last_sa = instance_config.get('last_sa', '')
        if last_sa in sa_jsons:
            logger.info('Get `last_sa` from config, resort list `sa_jsons`')
            last_sa_index = sa_jsons.index(last_sa)
            sa_jsons = sa_jsons[last_sa_index:] + sa_jsons[:last_sa_index]

        # if rclone attributes missing
        if cmd_rclone.find('rclone') == -1:
            logger.warning('Lost important param `rclone` in rclone commands; Autoadd it.')
            cmd_rclone = "/usr/bin/rclone {}".format(cmd_rclone)

        if cmd_rclone.find('--config') == -1:
            logger.warning('Lost important param `--config` in rclone commands; default rclone config will be used.')
            cmd_rclone += ' --config {}'.format(rclone_config_path)

        if cmd_rclone.find('-vv') == -1:
            logger.warning('Lost important param `-v` in rclone commands; Autoadd it.')
            cmd_rclone = cmd_rclone.replace(" -v ", " ")
            cmd_rclone += ' -vv'

        if cmd_rclone.find('--drive-server-side-across-configs') == -1:
            logger.warning('Lost important param `--drive-server-side-across-configs` in rclone commands; Autoadd it.')
            cmd_rclone += ' --drive-server-side-across-configs'

        if cmd_rclone.find('--drive-acknowledge-abuse') == -1:
            logger.warning('Lost important param `--drive-acknowledge-abuse` in rclone commands; Autoadd it.')
            cmd_rclone += ' --drive-acknowledge-abuse'

        if cmd_rclone.find('--rc') == -1:
            logger.warning('Lost important param `--rc --rc-addr` in rclone commands; Autoadd it.')
            cmd_rclone += ' --rc --rc-addr=localhost:0'

        if cmd_rclone.find('--log-file') == -1:
            logger.warning('Lost important param `--log-file` in rclone commands; Autoadd it.')
            cmd_rclone += ' --log-file {}'.format(rclone_log_path)

        if cmd_rclone.find('--fast-list') == -1:
            logger.warning('Lost important param `--fast-list` in rclone commands; Autoadd it.')
            cmd_rclone += ' --fast-list'

        # ??????
        while True:
            if break_for_next_cmd:
                break

            logger.info('Switch to next SA..........')
            last_sa = current_sa = get_next_sa_json_path(last_sa)
            write_config('last_sa', current_sa)
            logger.info('Get SA information, file: %s , email: %s' % (current_sa, get_email_from_sa(current_sa)))

            # avoid using temp banned SA Projects which haven't waited 24 hours
            if is_project_banned(current_sa):
                logger.warning("Project ID still under 24-hour ban.")
                continue
            else:
                logger.info("Project ID is not under a ban.")

            # avoid using banned SAs which haven't waited 24 hours
            if is_sa_banned(current_sa):
                logger.warning("Service account still under 24-hour ban.")
                continue
            else:
                logger.info("Service account is not under a ban.")

            # Avoid using in-use SAs
            if is_sa_being_used(current_sa):
                logger.info("Service account is unavailable.")
                continue
            else:
                logger.info("Service account is available.")
                update_track_log(current_sa)

            # Select SA by config or argument
            if switch_sa_way == 'config':
                switch_sa_by_config(current_sa)
                cmd_rclone_current_sa = cmd_rclone
            else:
                cmd_rclone_current_sa = cmd_rclone + ' --drive-service-account-file %s' % (current_sa,)

            # Inject rclone union env vars into `proc_env`
            # DOESN'T HANDLE MULTIPLE TDs IF ITERATING THROUGH CMDs
            if td_rotate_name:
                logger.warning('Injecting Team Drive rotation...')
                generated_team_drive_union = generate_rclone_union_from_config(td_rotate_name)
                proc_env.update(generated_team_drive_union)
                #print(generated_team_drive_union)
                #exit()

            # ???subprocess?rclone
            proc_log = open(rclone_log_path, 'a')
            proc_cmd = shlex.split(cmd_rclone_current_sa)
            proc = subprocess.Popen(proc_cmd, stdout=proc_log, stderr=proc_log, env=proc_env)

            # ??,??rclone?????
            logger.info('Wait %s seconds to full call rclone command: %s' % (check_after_start, cmd_rclone_current_sa))
            time.sleep(check_after_start)

            # Hook onto rclone PID if it didn't die early
            if proc.poll() is None:
                write_config('last_pid', proc.pid)
                logger.info('Run rclone command Success in pid %s' % (proc.pid))
                rc_port = get_listen_port(proc.pid)

            # If pid has already died early
            if proc.poll() != None:
                logger.warning("Premature death of process.")

                force_kill_rclone_subproc(proc.pid)
                proc.kill()

                # remove SA from track log
                update_track_log(current_sa, remove=True)

                # print last 20 lines of log
                logger.info('Providing the last 20 lines from rclone log...')
                print(get_rclone_log_tail(rclone_log_path, 20))

                # if not multiple commands
                if len(args.commands) == 1:
                    exit(1)


            # rclone rc core/stats
            cnt_error = 0
            cnt_403_retry = 0
            cnt_transfer_last = 0
            cnt_get_rate_limit = False

            # SA Switch Vars
            should_exit = 0
            should_switch = 0
            switch_reason = 'Switch Reason: '
            switch_teamdrives = False
            switch_projects_temp_bans = []

            while True:
                try:
                    response = subprocess.check_output('rclone rc --url "http://localhost:{}" core/stats'.format(rc_port), shell=True)
                except NameError as error:
                    # This is a temporary fix that needs "100%" check from rclone output
                    logger.warning("Rclone process died before it could be check. Probably not an issue.")
                    break_for_next_cmd = True
                    break
                except subprocess.CalledProcessError as error:

                    # something on checking log file to see if transfers finished instead of failing

                    cnt_error = cnt_error + 1
                    err_msg = 'check core/stats failed for %s times,' % cnt_error

                    if cnt_error > 3:
                        logger.error(err_msg + ' Force kill exist rclone process %s.' % proc.pid)
                        proc.kill()

                        # remove SA from track log
                        update_track_log(current_sa, remove=True)

                        # print the last 20 lines of log
                        logger.info('Providing the last 20 lines from rclone log...')
                        print(get_rclone_log_tail(rclone_log_path, 20))

                        # if not multiple commands
                        if len(args.commands) == 1:
                            exit(1)
                        else:
                            break_for_next_cmd = True
                            break

                    logger.warning(err_msg + ' Wait %s seconds to recheck.' % check_interval)
                    time.sleep(check_interval)
                    continue  # ????
                else:
                    cnt_error = 0

                # decode rclone rc core/stats
                response_json = json.loads(response.decode('utf-8').replace('\0', ''))
                cnt_transfer = response_json.get('bytes', 0)

                # print
                logger.info('Transfer Status - Upload: %s GiB, Avg upspeed: %s MiB/s, Transfered: %s.' % (
                    round(response_json.get('bytes', 0) / pow(1024, 3),2),
                    round(response_json.get('speed', 0) / pow(1024, 2),2),
                    response_json.get('transfers', 0)
                ))

                # DEBUG: rc output
                #logger.debug(response_json)

                # The whole point of the *individual* if-statements is to add up
                # points that signify when it's time to close the instance... otherwise rclone would run
                # indefinitely.

                # Project Quota Switch:
                if rclone_switch_rules.get('error_project_quota', False):
                    rclone_log_tail = get_rclone_log_tail(rclone_log_path, 20)
                    if rclone_log_tail.find('Rate of requests for user exceed configured project quota') > -1:
                        should_switch = should_switch + 0.001
                        switch_reason += 'Rule `error_project_quota` hit, '

                # SA Switch: 750 GB+
                if rclone_switch_rules.get('up_than_750', False):
                    if cnt_transfer > 750 * pow(1000, 3):  # ??? 750GB ??? 750GiB
                        should_switch += 1
                        switch_reason += 'Rule `up_than_750` hit, '

                # SA Switch: Zero transferred between check interval
                # and no server-side progress (still developing)
                if rclone_switch_rules.get('zero_transferred_between_check_interval', False):
                    if cnt_transfer - cnt_transfer_last == 0:  # ???
                        cnt_403_retry += 1
                        if cnt_403_retry % 10 == 0:
                            logger.warning('Rclone has not transferred in %s checks' % cnt_403_retry)
                        if cnt_403_retry >= 2000:  # ??100???????
                            should_switch += 1
                            switch_reason += 'Rule `zero_transferred_between_check_interval` hit, '
                    else:
                        cnt_403_retry = 0
                    cnt_transfer_last = cnt_transfer

                # SA Switch: Ratelimit exceeded
                if rclone_switch_rules.get('error_user_rate_limit', False):
                    last_error = response_json.get('lastError', '')
                    if last_error.find('userRateLimitExceeded') > -1:
                        should_switch += 1
                        switch_reason += 'Rule `error_user_rate_limit` hit, '

                # SA Switch: 2 minutes of
                # 'userRateLimitExceeded' and 0 transferred
                if rclone_switch_rules.get('user_limit_and_zero_data', False):
                    dtm_pattern = r"((\d{4})\/(\d{2})\/(\d{2}) (\d{2})\:(\d{2})\:(\d{2}))"
                    latest_five_lines = get_rclone_log_tail(rclone_log_path, 5).splitlines()
                    is_transferring = False
                    if response_json.get('transferring', False):
                        for transfer in response_json['transferring']:
                            if 'bytes' not in transfer or 'speed' not in transfer:
                                continue
                            elif transfer.get('bytes', 0) != 0 and transfer.get('speed', 0) > 0:  # ??????????
                                is_transferring = True
                                break
                    for line in latest_five_lines: # because there are lines that won't match
                        matches = re.search(dtm_pattern, line)
                        if 'low level retry' in line and 'userRateLimitExceeded' in line and matches:
                            if not is_transferring:
                                match = re.search(dtm_pattern, line)
                                dtm_log = datetime.datetime.strptime(match.group(), "%Y/%m/%d %H:%M:%S")
                                if not userlimit_first_log_dtm:
                                    userlimit_first_log_dtm = dtm_log
                                else:
                                    duration = dtm_log - userlimit_first_log_dtm
                                    duration_seconds = duration.total_seconds()
                                    if duration_seconds >= 300: # After so many seconds
                                        should_switch += 1
                                        switch_reason += 'Rule `user_limit_and_zero_data` hit, '
                                        userlimit_first_log_dtm = None
                                        break
                            else:
                                userlimit_first_log_dtm = None

                # SA Switch: All transfers in zero
                # and no server-side progress (still developing)
                if rclone_switch_rules.get('all_transfers_in_zero', False):
                    graceful = True
                    if response_json.get('transferring', False):
                        for transfer in response_json['transferring']:
                            # ??`bytes`??`speed`??????(???transfer?????) @yezi1000
                            if 'bytes' not in transfer or 'speed' not in transfer:
                                continue
                            elif transfer.get('bytes', 0) != 0 and transfer.get('speed', 0) > 0:  # ??????????
                                graceful = False
                                break
                    if graceful:
                        should_switch += 1
                        switch_reason += 'Rule `all_transfers_in_zero` hit, '

                # Debug
                logger.debug("Should switch count: {}".format(should_switch))

                # SA and/or TD Switch: Process the switch
                if should_switch >= switch_level:
                    logger.info("Switch triggered: {}".format(switch_reason))
                    force_kill_rclone_subproc(proc.pid)

                    # print the last 20 lines of log
                    logger.info('Providing the last 20 lines from rclone log...')
                    print(get_rclone_log_tail(rclone_log_path, 20))

                    # Add project ID to temp ban list
                    if 'error_project_quota' in switch_reason:
                        add_project_ban(current_sa)

                    if not switch_teamdrives:
                        # update ban log for SAs
                        logger.info('Updating 24-ban log for (%s)' % current_sa)
                        update_ban_log(current_sa)

                        sa_switch_count += 1

                        # remove SA from track log
                        update_track_log(current_sa, remove=True)

                    break

                time.sleep(check_interval)

            # Ensure rclone process is dead for next SA
            force_kill_rclone_subproc(proc.pid)

print(get_rclone_log_tail(rclone_log_path, 20))

# Clean up logs unless told to save
if not args.save_logs:
    log_cleanup()
else:
    logger.info('Log paths: ....')
