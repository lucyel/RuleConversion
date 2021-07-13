import re
import os
import urllib.request
import json

def create_url(url):
    repo_only_url = re.compile(r"https:\/\/github\.com\/[a-z\d](?:[a-z\d]|-(?=[a-z\d])){0,38}\/[a-zA-Z0-9]+")
    re_branch = re.compile("/(tree|blob)/(.+?)/")
    branch = re_branch.search(url)
    download_dirs = url[branch.end():]
    api_url = (url[:branch.start()].replace("github.com", "api.github.com/repos", 1) + "/contents/" + download_dirs + "?ref=" + branch.group(2))
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


    opener = urllib.request.build_opener()
    opener.addheaders = [('User-agent', 'Mozilla/5.0')]
    urllib.request.install_opener(opener)
    response = urllib.request.urlretrieve(api_url)

    if not flatten:
        # make a directory with the name which is taken from
        # the actual repo
        os.makedirs(dir_out, exist_ok=True)

    total_files = 0

    with open(response[0], "r") as f:
        data = json.load(f)
        # getting the total number of files so that we
        # can use it for the output information later
        total_files += len(data)

        # If the data is a file, download it as one.
        if isinstance(data, dict) and data["type"] == "file":
            # download the file
            opener = urllib.request.build_opener()
            opener.addheaders = [('User-agent', 'Mozilla/5.0')]
            urllib.request.install_opener(opener)
            urllib.request.urlretrieve(data["download_url"], os.path.join(dir_out, data["name"]))
            return total_files

        for file in data:
            file_url = file["download_url"]
            file_name = file["name"]

            if flatten:
                path = os.path.basename(file["path"])
            else:
                path = file["path"]
            dirname = os.path.dirname(path)

            if dirname != '':
                os.makedirs(os.path.dirname(path), exist_ok=True)
            else:
                pass

            os.makedirs(f"{output_dir}\{dirname}", exist_ok=True)

            if file_url is not None:
                download_path = f"{output_dir}\{path}"
                opener = urllib.request.build_opener()
                opener.addheaders = [('User-agent', 'Mozilla/5.0')]
                urllib.request.install_opener(opener)
                # download the file
                urllib.request.urlretrieve(file_url, download_path)
            else:
                download(file["html_url"], flatten, dir_out)
    return total_files
