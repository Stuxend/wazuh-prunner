# wazuh-prunner
A simple python lambda/script to prune wazuh agents.

## How to run locally:
To run this locally into your system you must have the requeriments installed, python3 and envs setup:

replace the following data into the script:
DATA  |  data  |
| :------------ |:---------------|
| wazuh_user | username for wazuh api. |
| wazuh_pass | password for wazuh api access |

Argument |  details  |
| :------------ |:---------------|
| -g | group to check (ex: servers) |
| -U | url of wazuh |
| -t | time to prune (ex: 6h , 1d) |

Example:

```bash
python3 wazuh-api.py -g servers -U http://127.0.0.1/api/wazuh -t 1h

```

(this command will prune agent into "server" groups that are disconnected since last 1h.)
