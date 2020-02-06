# Respect
Forked from https://github.com/Rhilip/AutoRclone

# Autorclone 

A Python script which uses Google Cloud Service Accounts to bypass the 750GB upload file size limit and manipulates rclone remotes to bypass the 400k file count limit per Share Drives (formerly Team Drives) on Google Drive.

This repo uses [rclone](https://rclone.org) to **transfer files from local/remote disk to Google Drive or Team/Share Drive**.

## Requirements for using the script

* Python ^3.4
* Rclone ^1.41 (To support Service Account feature.)

## Setup
- ...

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
