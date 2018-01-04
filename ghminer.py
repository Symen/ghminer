#!/usr/bin/python3.5

import argparse
import urllib.request
import urllib.parse
import requests
import base64
import json
import time
from enum import Enum

GIT_API_URL="https://api.github.com/"
GIT_API_URL_GRAPHQL = GIT_API_URL + 'graphql'
GIT_API_URL_SEACH = GIT_API_URL + 'search'
github_username = "USERNAME"
github_api_token = "API_TOKEN"

class VulnType(Enum):
    BufferOverflow = 1
    XSS = 2
    SQLi = 3

cur_vuln_type = VulnType.BufferOverflow

# Instantiate the parser
parser = argparse.ArgumentParser(description='GHMiner checks for critical patterns in GitHub-Repositories.')
args = None

CRITICAL_BO_FUNCTIONS = {"c" : ["strcpy(", "strcat(", "sprintf(", "printf(", "sprintf(", "snprintf(", "memcpy("]}
NO_CRITICAL_BO_FUNCTIONS = {"c" : ['printf("']}
CRITICAL_XSS_FUNCTIONS = {"php": ["strip_tags(", "addslashes\((", "$_POST", "$_GET"],
                          "html" : ["input\("], 
                          "javascript" : ["eval\((", "document\.write"]}
CRITICAL_SQLI_FUNCTIONS = {"php" : ["mysql_query("]}
NOT_CRITICAL_SQLI_FUNCTIONS = {"php" : ["isset", "curl_exec", "drush_shell_exec"]}



def build_markdown(file_name, title, repos):
    with open(file_name, "w") as f:
        f.write("# " + title + "\n\n")
        f.write("Info: Count=" + str(len(repos))
                + " StareRange= " + str(args.min_stars) + ".." + str(args.max_stars)
                + " FirstNumRepos= " + str(args.first) + "\n\n")

        for repo_name, c_indicator in repos.items():
            if not c_indicator:
                continue

            f.write("---" + "\n\n")
            f.write("- [ ] " + repo_name + ":" + "\n") 

            for indicator, c_json in c_indicator.items():
                f.write("\t- " + indicator + ":" + "\n")

                for item in c_json["items"]:
                    file_name = item["name"]
                    file_url = item["html_url"]
                    text_matches = item["text_matches"]
                    f.write("\t\t- [ ] *" + file_name + "*:" + file_url + "\n")
                    for i, match in enumerate(text_matches):
                        f.write("\t\t\t```\n")
                        f.write("\t\t\t" + match["fragment"].replace("\n", "\n\t\t\t") + "\n")
                        f.write("\t\t\t```\n")
                        f.write("\t\t\t---\n")

def get_repos(search_query:str):
    json_query = {
            'query' : '{ search(query: "' + search_query + '", type: REPOSITORY, first: ' + str(args.first) + ') {' 
            'repositoryCount ' 
            'edges {' 
            'node {' 
            '... on Repository {' 
            'url '
            'name '
            'owner {login} '
            'descriptionHTML '
            'stargazers { totalCount } ' 
            'forks { totalCount } '
            'updatedAt'
            '}'
            '}'
            '}'
            '}'
            '}'
            }

    headers = {'Authorization': 'token %s' % github_api_token}
    repos_response = requests.post(url=GIT_API_URL_GRAPHQL, json=json_query, headers=headers)
    repos_json = json.loads(repos_response.text)
    repos = dict()

    for repo_edge in repos_json["data"]["search"]["edges"]:
        repo_name = repo_edge["node"]["name"]
        repo_owner = repo_edge["node"]["owner"]["login"]
        repos[repo_owner] = repo_name

    return repos

def filter_fp(search_language, x):
    global cur_vuln_type

    if cur_vuln_type is VulnType.BufferOverflow:
        c_map = CRITICAL_BO_FUNCTIONS
        fp_map = NO_CRITICAL_BO_FUNCTIONS
    elif cur_vuln_type is VulnType.XSS:
        c_map = CRITICAL_XSS_FUNCTIONS
        fp_map = NOT_CRITICAL_XSS_FUNCTIONS
    else:
        c_map = CRITICAL_SQLI_FUNCTIONS
        fp_map = NOT_CRITICAL_SQLI_FUNCTIONS

    for y in c_map[search_language]:
        if y in x:
            for z in fp_map[search_language]:
                if z in x:
                    return False
            return True
    return False 

def search_in_code(search_repo, search_query, search_language):
    print("Search in code: repo=" + search_repo + " query= " + search_query + " ...")
    url = GIT_API_URL_SEACH + "/code?q=" + search_query + "+in:file+language:" + search_language + "+repo:" + search_repo
    print(url)
    has_critical_function = False;

    try:
        request = urllib.request.Request(url)
        base64string = base64.encodestring(("%s/token:%s" % (github_username, github_api_token)).encode()).decode().replace("\n","")
        request.add_header("Authorization", "Basic %s" % base64string)
        request.add_header("Accept", "application/vnd.github.v3.text-match+json")
        result = urllib.request.urlopen(request)
        result_json = json.loads(result.read().decode("utf-8"))
        #print(result_json["items"])
        total_count = result_json["total_count"]
        print("\ttotal_count=" + str(total_count))
        result.close()
    except:
        time.sleep(60)
        return None

    for item in result_json["items"]:
        text_matches = [x for x in item["text_matches"] if filter_fp(search_language, x["fragment"])] 
        if not text_matches:
            return None

    for item in result_json["items"]:
        file_path = item["path"]
        file_url = item["html_url"]
        text_matches = item["text_matches"]
        print("\tfile_path= " + file_path)
        print("\tfile_url= " + file_url)
        print("\ttext_matches:")
        print("\t\t" + 100*"-" + "\n")
        for i, match in enumerate(text_matches):
            print("\t\t" + match["fragment"].replace("\n", "\n\t\t") + "\n")
            print("\t\t" + 100*"-" + "\n")
        print("")

    if total_count <= 0:
        return None 

    return result_json

def search_open_bugs(search_repo, search_query, search_language):
    if search_repo is not "":
        url = GIT_API_URL_SEACH + "/issues?q=" + search_query + "+label:bug+language:" + search_language + "+repo:" + search_repo + "+state:open&sort=created&order=asc"
    else:
        url = GIT_API_URL_SEACH + "/issues?q=" + search_query + "+label:bug+language:" + search_language + "+state:open&sort=created&order=asc"

    print("Search open bugs: " + url + " ...")

    request = urllib.request.Request(url)
    base64string = base64.encodestring(("%s/token:%s" % (github_username, github_api_token)).encode()).decode().replace("\n", "")
    request.add_header("Authorization", "Basic %s" % base64string)
    result = urllib.request.urlopen(request)
    result_json = json.loads(result.read().decode("utf-8"))
    result.close()

    total_count = result_json["total_count"]

    if total_count <= 0:
        return None 

    return result_json

def find_bo_repos():
    print("Seach for repos with potential buffer overflows ...") 
    bo_indicators = ["buffer%20overflow", "memory%20corruption", "use after%20free", "double%20free"]
    bo_indicator.append(CRITICAL_BO_FUNCTIONS["c"])
    bo_bugs = dict()

    for indicator in bo_indicators:
        bug_json = search_open_bugs("", indicator, "C")

        if bug_json is None:
            continue

        bo_bugs[indicator] = bug_json

        print("\tPotential Buffer Overflows: indicator=" + indicator 
                + " total_count=" + str(bug_json["total_count"]) + "\n")

        for item in bug_json["items"]:
            repo_url= item["repository_url"]
            bug_title = item["title"]
            bug_state = item["state"]
            file_url = item["html_url"]
            print("\t\tbug_title= " + bug_title)
            print("\t\trepo_url= " + repo_url)
            print("\t\tfile_url= " + file_url)
            print("")

    return bo_bugs

def analyze_boc_repos():
    global cur_vuln_type
    print("Analyze repositories for Bufferoverflow candidates ...") 
    boc_repos = dict()
    cur_vuln_type = VulnType.BufferOverflow
    language = "c"
    graphql_search_query = 'language:' + language + ' stars:' + str(args.min_stars) + '..' + str(args.max_stars)
    i = 0

    repos = get_repos(graphql_search_query)

    print("\tRelevant repositories:")
    for owner, name in repos.items():
        print("\t\t" + owner + "/" + name)

    # search in relevant repos for critical functions
    for repo_owner, repo_name in repos.items():
        print(100*"=" + "\nSearch in Repo " + str(i) + ":")
        i += 1
        repo_id = repo_owner + "/"+ repo_name
        boc_indicator = dict()

        for indicator in CRITICAL_BO_FUNCTIONS[language]:
            boc_json = search_in_code(repo_id, indicator, language)

            if boc_json is None:
                continue

            boc_indicator[indicator] = boc_json

        boc_repos[repo_id] = boc_indicator

    # find open issues related with memory corruptions 
    #bo_bugs = find_bo_repos()
    build_markdown(args.output, "Potential BufferOverflow-Repositories", boc_repos)


def analyze_xssc_repos():
    global cur_vuln_type
    print("Analyze repositories for XSS candidates ...") 
    xssc_repos = dict()
    cur_vuln_type = VulnType.XSS

    for language, ciritical_functions in CRITICAL_XSS_FUNCTIONS.items():
        graphql_search_query = 'language:' + language + ' stars:' + str(args.min_stars) + '..' + str(args.max_stars)
        repos = get_repos(graphql_search_query)
        i = 0

        # search in relevant repos for critical functions
        for repo_owner, repo_name in repos.items():
            print(100*"=" + "\nSearch in Repo " + str(i) + ":")
            i += 1
            repo_id = repo_owner + "/"+ repo_name
            xssc_indicator = dict()

            for indicator in ciritical_functions:
                xssc_json = search_in_code(repo_id, indicator, language)

                if xssc_json is None:
                    continue

                xssc_indicator[indicator] = xssc_json

            xssc_repos[repo_id] = xssc_indicator

    build_markdown(args.output, "Potential XSS-Repositories", xssc_repos)


def analyze_sqlic_repos():
    global cur_vuln_type
    print("Analyze repositories for SQL-Injection candidates ...") 
    sqlic_repos = dict()
    cur_vuln_type = VulnType.SQLi

    for language, ciritical_functions in CRITICAL_SQLI_FUNCTIONS.items():
        graphql_search_query = 'language:' + language + ' stars:' + str(args.min_stars) + '..' + str(args.max_stars)
        repos = get_repos(graphql_search_query)
        i = 0

        # search in relevant repos for critical functions
        for repo_owner, repo_name in repos.items():
            print(100*"=" + "\nSearch in Repo " + str(i) + ":")
            i += 1
            repo_id = repo_owner + "/"+ repo_name
            sqlic_indicator = dict()

            for indicator in ciritical_functions:
                sqli_json = search_in_code(repo_id, indicator, language)

                if sqli_json is None:
                    continue

                sqlic_indicator[indicator] = sqli_json

            sqlic_repos[repo_id] = sqlic_indicator

    build_markdown(args.output, "Potential SQL-Injection-Repositories", sqlic_repos)


def init_arguments():
    global parser 
    global args

    parser.add_argument('--bo', action='store_true',
                        help='Check patterns in C-programs that might lead to buffer-overflow')

    parser.add_argument('--xss', action='store_true',
                        help='Check patterns that might lead to xss')

    parser.add_argument('--sqli', action='store_true',
                        help='Check patterns that might lead to sql-injections')

    parser.add_argument('--first', type=int, nargs='?', default=3,
                        help='Crawl the first n repositories')

    parser.add_argument('--min_stars', type=int, nargs='?', default=50,
                        help='Min number of stars the repository should have')

    parser.add_argument('--max_stars', type=int, nargs='?', default=50,
                        help='Max number of stars the repository should have')

    parser.add_argument('--output', type=str, nargs='?', default='results.md',
                        help='Name of the output file (markdown)')

    args = parser.parse_args()


if __name__ == "__main__":
    init_arguments()

    if args.bo:
        analyze_boc_repos()

    if args.xss:
        analyze_xssc_repos()

    if args.sqli:
        analyze_sqlic_repos()
