# GH-Miner

## Description
GHMiner checks for critical patterns in GitHub-Repositories.

## Setup
Since GHMiner is using the GitHub API it is necessary to generate a personal access token ([HowTo](https://help.github.com/articles/creating-a-personal-access-token-for-the-command-line/)).

Copy the file `config-sample.py` as `config.py` and replace the username and access token in it.

Make ghminer executable:

* `chmod +x ghminer.py`

Install requirements

* `pip install -r requirements`

## Example Commands 

Display the options of ghminer.py

* `./ghminer.py --help`

Search for sql-injections in a Repository with 50 Stars:

* `./ghminer.py --sqli`

Search for first 100 buffer-overflows in a Repository with 50 to 100 Stars:

* `./ghminer.py --bo --first=100 --min_stars=50 --max_stars=100 --output bo_repos.md`

*PS: We can only send a limited amout of requests to the GitHub API (20 per minute) which causes some delays*
