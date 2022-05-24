# wazuh-prunner
A simple python lambda/script to prune wazuh agents using the new wazuh API. This code is for a lambda function and need a secret manager to save the API key. You can run this locally changing the SETUP_SECRET code block.

## How to run locally:
To run this locally into your system you must have the requeriments installed, python3 and envs setup:

replace the following data into the script:

DATA  |  data  |
| :------------ |:---------------|
| -t | time to prune (ex: 6h , 1d) |
| -U | host of your wazuh implementation |

ENV |  data  |
| :------------ |:---------------|
| WAZUH_API_SECRET | name of your secret into secret manager |

Example:

```bash
python3 wazuh-api.py -g servers -U 172.12.1.1 -t 1h

```

(this command will prune agent into "server" groups that are disconnected since last 1h.)
