#!/usr/bin/python3

import os
import re
import json
import time
import glob
import psutil
import logging
import subprocess
import configparser
import argparse
import filelock
import sys
import shlex
import socket
import hashlib
import random
import psutil
import collections
from contextlib import closing
from colorama import Back, Fore, Style
from pathlib import Path
from logging.handlers import RotatingFileHandler

'''
2. Correct failed rc connection by checking for log output (eg. complete, 100%)
3. Investigate log not printing on rc check fail, esp. on seedbox
5. Change logging and tracking into "with" operation to ensure SIGINT is handled correctly (eg. deleting/updating files)
'''

# ------------?????------------------

time_id = '{}'.format(int(time.time()))

# system and user
user_home = str(Path.home())

# ??rclone?? (s)
check_after_start = 30  # ???rclone???,??xxs??????rclone??,?? rclone rc core/stats ????
check_interval = 10  # ???????rclone rc core/stats?????

# rclone????????
td_switch_count = 0
sa_switch_count = 0
sa_switch_limit = 1000
switch_level = 1  # ?????????,???????????,??????True(???)???,? 1 - 4(max)
rclone_switch_rules = {
    'up_than_750': False,  # ????????750G
    'error_user_rate_limit': True,  # Rclone ????rate limit??
    'zero_transferred_between_check_interval': False,  # 100???????rclone?????0
    'all_transfers_in_zero': False,  # ????transfers??size??0
    'error_td_file_limit': True,
    'error_project_quota': True
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

# proc vars
proc_env = os.environ.copy()

# ------------?????------------------

# ????
instance_config = {}
sa_jsons = []

# ????
logFormatter = logging.Formatter(fmt=logging_format, datefmt=logging_datefmt)

logger = logging.getLogger()
logger.setLevel(logging.NOTSET)
while logger.handlers:  # Remove un-format logging in Stream, or all of messages are appearing more than once.
    logger.handlers.pop()

if script_log_file:
    fileHandler = RotatingFileHandler(filename=script_log_file, mode='a',
                                      backupCount=2, maxBytes=5 * 1024 * 1024,
                                      encoding=None, delay=0)
    fileHandler.setFormatter(logFormatter)
    logger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)

def generate_rclone_union_from_config(tdbasename,rotate=False):
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

    if rotate:
        d = collections.deque(td_collection)
        d.rotate(rotate)
        td_collection = list(d)

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
    
    time.sleep(1)

    return ">>>>>>>>TEST"

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
    if _last_sa not in sa_jsons:  # ?????????sa_json_path,?????
        next_sa_index = 0
    else:
        _last_sa_index = sa_jsons.index(_last_sa)
        next_sa_index = _last_sa_index + 1
    # ???????????
    if next_sa_index > len(sa_jsons):
        next_sa_index = next_sa_index - len(sa_jsons)
    return sa_jsons[next_sa_index]


def switch_sa_by_config(cur_sa):
    # ??SA??
    logger.info('Change rclone.conf SA information to %s' % (cur_sa))
    rclone_remote_env_key = "RCLONE_CONFIG_{destname}_SERVICE_ACCOUNT_FILE".format(destname=rclone_dest_name)
    proc_env[rclone_remote_env_key] = "{varval}".format(varval=cur_sa)
    logger.info('Change SA information in rclone.conf Success')
    print(proc_env)


def get_email_from_sa(sa):
    return json.load(open(sa, 'r'))['client_email']


# ????Rclone
def force_kill_rclone_subproc_by_parent_pid(sh_pid):
    if psutil.pid_exists(sh_pid):
        sh_proc = psutil.Process(sh_pid)
        logger.info('Get The Process information - pid: %s, name: %s' % (sh_pid, sh_proc.name()))
        for child_proc in sh_proc.children():
            if child_proc.name().find('rclone') > -1:
                logger.info('Force Killed rclone process which pid: %s' % child_proc.pid)
                child_proc.kill()

parser = argparse.ArgumentParser(description="Process command line arguments for " + __file__)
parser.add_argument('--service-accounts-dir', type=str, default="/home/chamber/Desktop/srv_config/config_files/sa_json", nargs='?', help='service account JSON directory')
parser.add_argument('--switch-by-config', action='store_true', help='make autorclone switch by config instead of runtime')
parser.add_argument('--sa-config-name', type=str, help='set rclone config section name for --switch-by-config; req.')
parser.add_argument('--rclone-bin', type=str, default="/usr/bin/rclone", nargs='?', help='rclone binary path')
parser.add_argument('--rclone-config', type=str, default="/home/chamber/Desktop/srv_config/config_files/rclone.conf", nargs='?', help='rclone config path')
parser.add_argument('--rclone-exclude-exts', type=str, nargs='+', help='rclone extension exclude list')
parser.add_argument('--td-rotate-name', type=str, nargs='?', help='rotate the writable team drive on error')
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

for command in args.commands:
    # Fill out rclone command from arg
    cmd_rclone = "{} {}".format(args.rclone_bin, command)

    # Debug
    logger.info("DEBUG MESSAGE PRE LOCK")

    # Run with lock on instance to make clean break
    instance_check = filelock.FileLock(instance_lock_path)
    with instance_check.acquire(timeout=0):

        # Debug
        logger.info("DEBUG MESSAGE POST LOCK")

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
            force_kill_rclone_subproc_by_parent_pid(last_pid)

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

        if cmd_rclone.find('--rc') == -1:
            logger.warning('Lost important param `--rc --rc-addr` in rclone commands; Autoadd it.')
            cmd_rclone += ' --rc --rc-addr=localhost:0'

        if cmd_rclone.find('--log-file') == -1:
            logger.warning('Lost important param `--log-file` in rclone commands; Autoadd it.')
            cmd_rclone += ' --log-file {}'.format(rclone_log_path)

        # ??????
        while True:
            if break_for_next_cmd:
                break

            #if sa_switch_count == sa_switch_limit:
            #    break

            logger.info('Switch to next SA..........')
            last_sa = current_sa = get_next_sa_json_path(last_sa)
            write_config('last_sa', current_sa)
            logger.info('Get SA information, file: %s , email: %s' % (current_sa, get_email_from_sa(current_sa)))

            # avoid using banned SAs which haven't waited 24 hours
            if is_sa_banned(current_sa):
                logger.warn("Service account still under 24-hour ban.")
                continue
            else:
                logger.info("Service account is not under a ban.")

            # avoid using in-use SAs
            if is_sa_being_used(current_sa):
                logger.info("Service account is unavailable.")
                continue
            else:
                logger.info("Service account is available.")
                update_track_log(current_sa)

            # ??Rclone????
            if switch_sa_way == 'config':
                switch_sa_by_config(current_sa)
                cmd_rclone_current_sa = cmd_rclone
            else:
                # ??????`runtime`,??'--drive-service-account-file'??
                cmd_rclone_current_sa = cmd_rclone + ' --drive-service-account-file %s' % (current_sa,)

            # Inject rclone union env vars into `proc_env`
            # DOESN'T HANDLE MULTIPLE TDs IF ITERATING THROUGH CMDs
            if td_rotate_name:
                logger.warning('Injecting Team Drive rotation...')
                generated_team_drive_union = generate_rclone_union_from_config(td_rotate_name,td_switch_count)
                proc_env.update(generated_team_drive_union)

            # ???subprocess?rclone
            proc_log = open(rclone_log_path, 'a')
            proc_cmd = shlex.split(cmd_rclone_current_sa)
            proc = subprocess.Popen(proc_cmd, stdout=proc_log, stderr=proc_log, env=proc_env)

            # ??,??rclone?????
            logger.info('Wait %s seconds to full call rclone command: %s' % (check_after_start, cmd_rclone_current_sa))
            time.sleep(check_after_start)

            # ??pid??
            # ??,??subprocess???sh,??sh??rclone,??????????sh?pid??
            # proc.pid + 1 ????????rclone???pid,????
            # ?????? force_kill_rclone_subproc_by_parent_pid(sh_pid) ????rclone
            if proc.poll() is None:
                write_config('last_pid', proc.pid)
                logger.info('Run Rclone command Success in pid %s' % (proc.pid + 1))
                rc_port = get_listen_port(proc.pid)

            # if pid has already died
            if proc.poll() != None:
                logger.warn("Premature death of process.")

                proc.kill()

                # remove SA from track log
                update_track_log(current_sa, remove=True)

                # print last 20 lines of log
                logger.info('Providing the last 20 lines from rclone log...')
                print(get_rclone_log_tail(rclone_log_path, 20))
                
                # if not multiple commands
                if len(args.commands) == 1:
                    exit(1)


            # ????? `rclone rc core/stats` ???????
            cnt_error = 0
            cnt_403_retry = 0
            cnt_transfer_last = 0
            cnt_get_rate_limit = False
            while True:
                try:
                    response = subprocess.check_output('rclone rc --url "http://localhost:{}" core/stats'.format(rc_port), shell=True)
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

                # ?? `rclone rc core/stats` ??
                response_json = json.loads(response.decode('utf-8').replace('\0', ''))
                cnt_transfer = response_json.get('bytes', 0)

                # ??????
                logger.info('Transfer Status - Upload: %s GiB, Avg upspeed: %s MiB/s, Transfered: %s.' % (
                    round(response_json.get('bytes', 0) / pow(1024, 3),2),
                    round(response_json.get('speed', 0) / pow(1024, 2),2),
                    response_json.get('transfers', 0)
                ))

                # SA Switch Vars
                should_exit = 0
                should_switch = 0
                switch_reason = 'Switch Reason: '
                switch_teamdrives = False
                switch_projet_quota = False

                # Project quota:
                if rclone_switch_rules.get('error_project_quota', False):
                    rclone_log_tail = get_rclone_log_tail(rclone_log_path, 20)
                    if rclone_log_tail.find('Rate of requests for user exceed configured project quota') > -1:
                        switch_project_quota = True
                        should_switch = (4 - should_switch) + should_switch
                        switch_reason += 'Rule `error_project_quota` hit, '

                # TD Switch
                if rclone_switch_rules.get('error_td_file_limit', False):
                    last_error = response_json.get('lastError', '')
                    if last_error.find('teamDriveFileLimitExceeded') > -1:
                        switch_teamdrives = True
                        should_switch = (4 - should_switch) + should_switch
                        switch_reason += 'Rule `error_td_file_limit` hit, '

                # SA Switch: 750 GB+ 
                if rclone_switch_rules.get('up_than_750', False):
                    if cnt_transfer > 750 * pow(1000, 3):  # ??? 750GB ??? 750GiB
                        should_switch += 1
                        switch_reason += 'Rule `up_than_750` hit, '

                # SA Switch: Zero transferred between check interval
                if rclone_switch_rules.get('zero_transferred_between_check_interval', False):
                    if cnt_transfer - cnt_transfer_last == 0:  # ???
                        cnt_403_retry += 1
                        if cnt_403_retry % 10 == 0:
                            logger.warning('Rclone seems not transfer in %s checks' % cnt_403_retry)
                        if cnt_403_retry >= 100:  # ??100???????
                            should_switch += 1
                            switch_reason += 'Rule `zero_transferred_between_check_interval` hit, '
                    else:
                        cnt_403_retry = 0
                    cnt_transfer_last = cnt_transfer

                # SA Switch: Ratelimit exceed
                if rclone_switch_rules.get('error_user_rate_limit', False):
                    last_error = response_json.get('lastError', '')
                    if last_error.find('userRateLimitExceeded') > -1:
                        should_switch += 1
                        switch_reason += 'Rule `error_user_rate_limit` hit, '

                # SA Switch: All transfers in zero
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

                # SA or TD Switch: Process the switch
                if should_switch >= switch_level:
                    logger.info("Switch triggered: {}".format(switch_reason))
                    force_kill_rclone_subproc_by_parent_pid(proc.pid) 

                    if switch_teamdrives:
                        td_switch_count += 1

                    if not switch_teamdrives:
                        # update ban log for SAs
                        logger.info('Updating 24-ban log for (%s)' % current_sa)
                        update_ban_log(current_sa)

                        sa_switch_count += 1

                        # remove SA from track log
                        update_track_log(current_sa, remove=True)

                    # Debug
                    logger.debug(should_switch)
                    logger.debug(switch_level) 

                    break
                
                time.sleep(check_interval)

            # Ensure rclone process is dead for next SA
            force_kill_rclone_subproc_by_parent_pid(proc.pid) 

print(get_rclone_log_tail(rclone_log_path, 20))

# clean up garbage log
logger.info('Cleaning up log file garbage.')   
os.remove(instance_lock_path)
os.remove(instance_config_path)
os.remove(rclone_log_path)
os.remove(script_log_file)












#if __name__ == '__main__':
#    parser = argparse.ArgumentParser(description="Process command line arguments for " + __file__)
#    parser.add_argument('-C','--cmd', type=str, required=True, nargs='?', help='rclone command string')
#    
#    args = parser.parse_args()
#
#    sys.exit(main(args.cmd))
