import re
import os
import urllib.request
import json
import yaml
from yaml.loader import SafeLoader

with open("config.yaml", "r") as ymlfile:
    vari = yaml.load(ymlfile, Loader=SafeLoader)


def create_url(url):
    re_branch = re.compile("/(tree|blob)/(.+?)/")
    branch = re_branch.search(url)
    download_dirs = url[branch.end():]
    api_url = (url[:branch.start()].replace("github.com", "api.github.com/repos", 1) + "/contents/" + download_dirs +
               "?ref=" + branch.group(2))
    return api_url, download_dirs


def download(repo_url, output_dir):
    api_url, download_dirs = create_url(repo_url)

    proxy = urllib.request.ProxyHandler({"http": f"{vari['network']['proxy_http']}", "https": f"{vari['network']['proxy_http']}"})
    opener = urllib.request.build_opener()
    #opener = urllib.request.build_opener(proxy)
    opener.addheaders = [('User-agent', 'Mozilla/5.0')]
    urllib.request.install_opener(opener)
    response = urllib.request.urlretrieve(api_url)

    total_files = 0

    with open(response[0], "r") as f:
        data = json.load(f)
        total_files += len(data)

        for file in data:
            file_url = file["download_url"]
            path = file["path"]
            path_1 = path.split("/")
            path2 = f"{path_1[-2]}/{path_1[-1]}"
            os.makedirs(f"{output_dir}/{path_1[-2]}", exist_ok=True)
            download_path = f"{output_dir}/{path2}"
            opener = urllib.request.build_opener()
            #opener = urllib.request.build_opener(proxy)
            opener.addheaders = [('User-agent', 'Mozilla/5.0')]
            urllib.request.install_opener(opener)
            urllib.request.urlretrieve(file_url, download_path)

    return total_files


download("https://github.com/stamparm/maltrail/tree/master/trails/static/suspicious", "D:\Downloads\download_test")
