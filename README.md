# Respect
Forked from https://github.com/Rhilip/AutoRclone

# Autorclone 

A Python script which uses Google Cloud Service Accounts to bypass:
- 750GB upload file size limit,
- manipulates rclone remotes to bypass the 400k file count limit per Share Drives (formerly Team Drives),
- and bypasses the user rate limit per project respective of the Service Accounts

## Requirements for using the script

* Python v3.4+
* [rclone](https://rclone.org) v1.41+ but not greater than v1.51 per [issue 4416](https://github.com/rclone/rclone/issues/4416)

## Setup
### Config ###
The rclone config (`rclone.conf`) currently needs to have to-be-unionized remotes formatted with `_[INTEGER]` following its title. For example: `RCLONE_UNION_NAME` is the title which will be used across multiple Team Drives ("TDs") and will be known as the Union Drive. Each Team Drive ("TD") to be used under that Union Drive must be numbered *sequentially*. This script will currently fail to recognize any TD after the first failure to follow a 1,2,3 sequence.
```
[RCLONE_UNION_NAME_1]
[snip]

[RCLONE_UNION_NAME_2]
[snip]

[RCLONE_UNION_NAME_3]
[snip]
```
To be clear, if 1 and 3 are present within `rclone.conf` only 1 will currently be recognized. And subsequently, this script *will* fail since rclone does not allow for single remote unions.

## Usage examples
```
./autorclone.py \
  --service-accounts-dir "/path/to/rclone_service_account_jsons" \
  --rclone-bin "/path/to/rclone_binary" \
  --rclone-config "/path/to/rclone.conf" \
  --td-rotate-name "RCLONE_UNION_NAME" \
  "copy RANDOM_REMOTE:/ RCLONE_UNION_NAME:/ --tpslimit=1 --transfers=1 --checkers=1"
```
```
./autorclone.py \
  --service-accounts-dir "/path/to/rclone_service_account_jsons" \
  --rclone-bin "/path/to/rclone_binary" \
  --rclone-config "/path/to/rclone.conf" \
  --td-rotate-name "RCLONE_UNION_NAME" \
  "copy RANDOM_REMOTE:/ RCLONE_UNION_NAME:/ --tpslimit=1 --transfers=1 --checkers=1" \
  "copy DIFF_REMOTE:/ RCLONE_UNION_NAME:/ --tpslimit=1 --transfers=1 --checkers=1";
```

## Rough Todo
- Allow multiple rclone unions to be generated for subprocess env vars
- Set universal location defaults for argparse; eg. rclone binary, rclone config, etc
- Properly encapsulate log cleanup in with-statement to prevent leaving a mess upon SIGINT or otherwise
- Add compatibility with Windows per temp dirs, etc
