import re
import os
import urllib.request
import json


def create_url(url):
    re_branch = re.compile("/(tree|blob)/(.+?)/")
    branch = re_branch.search(url)
    download_dirs = url[branch.end():]
    api_url = (url[:branch.start()].replace("github.com", "api.github.com/repos", 1) + "/contents/" + download_dirs +
               "?ref=" + branch.group(2))
    return api_url, download_dirs


def download(repo_url, output_dir, flatten=False,):
    api_url, download_dirs = create_url(repo_url)

    if not flatten:
        if len(download_dirs.split(".")) == 0:
            dir_out = os.path.join(output_dir, download_dirs)
        else:
            dir_out = os.path.join(output_dir, "/".join(download_dirs.split("/")[:-1]))
    else:
        dir_out = output_dir

    proxy = urllib.request.ProxyHandler({"http": f"{vari['network']['proxy_http']}", "https": f"{vari['network']['proxy_http']}"})
    opener = urllib.request.build_opener(proxy)
    opener.addheaders = [('User-agent', 'Mozilla/5.0')]
    urllib.request.install_opener(opener)
    response = urllib.request.urlretrieve(api_url)

    total_files = 0

    with open(response[0], "r") as f:
        data = json.load(f)
        # getting the total number of files so that we
        # can use it for the output information later
        total_files += len(data)

        for file in data:
            file_url = file["download_url"]

            if flatten:
                path = os.path.basename(file["path"])
            else:
                path = file["path"]
            dirname = os.path.dirname(path)
            print(dirname)
            path_1 = path.split("/")

            path2 = f"{path_1[-2]}/{path_1[-1]}"

            os.makedirs(fr"{output_dir}/{path_1[-2]}", exist_ok=True)

            if file_url is not None:
                download_path = fr"{output_dir}/{path2}"
                opener = urllib.request.build_opener(proxy)
                opener.addheaders = [('User-agent', 'Mozilla/5.0')]
                urllib.request.install_opener(opener)
                # download the file
                urllib.request.urlretrieve(file_url, download_path)
            else:
                download(file["html_url"], flatten, dir_out)
    return total_files

#download("https://github.com/Neo23x0/signature-base/tree/master/iocs", "D:\Downloads\download_test", False)
