# TODO: download folder not from git
# TODO: check if donwloaded file is type acsii text, if is other type then not download.
# TODO: convert other iocs format: IP:PORT [done]

import re
import base64
import subprocess
import os
import yaml
import hashlib
import urllib3
# import git
from GitDownloader import download
import magic
from yaml.loader import SafeLoader
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from os import listdir
from os.path import isfile, join, isdir

urllib3.disable_warnings()

with open("config.yaml", "r") as ymlfile:
    vari = yaml.load(ymlfile, Loader=SafeLoader)


def init_connection(host, protocol, user, password, use_ssl=False, verify_cert=False):
    return Elasticsearch(hosts=[host], scheme=protocol, http_auth=(user, password), use_ssl=use_ssl, verify_certs=verify_cert, ssl_show_warn=False)


def check_indices(indices):
    return elastic_client.indices.exists(index=indices)


def create_index(indices, request_body):
    elastic_client.indices.create(index=indices, body=request_body)


def search_iocs(value):
    return elastic_client.search(index="iocs", body={"query": {"match": {"iocs": value}}})


def check_type(iocs):
    if (bool(re.match(r"^#", iocs))) or (bool(re.match(r"^$", iocs))):
        return "none"
    if (bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", iocs))):
        return "ip"
    elif (bool(re.match(r".*\..*", iocs))):
        return "domain"


def add_iocs(indices, iocs, iocs_type, campaign):
    request_data = [
        {
            "_index": indices,
            "iocs": iocs,
            "iocs_type": iocs_type,
            "campaign": campaign
        }
    ]
    return bulk(elastic_client, request_data)


def init_hash_file(filehashgen, folder_path, folder_name, filename):
    hash_file_path = open(f"{filehashgen}", "w")
    for i in range(0, len(filename)):
        gen_hash = gen_hash_from_file(fr"{folder_path}/{folder_name}/{filename}")
        print(f"{folder_name}/{filename} : {gen_hash}", file=hash_file_path)


def update_hash_file(new_file, old_file):
    with open(old_file, "r") as firstfile, open(new_file, "w") as secondfile:
        for line in firstfile:
            secondfile.write(line)


# Input : file path needed to hash
def gen_hash_from_file(filepath):
    BUF_SIZE = 65536
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256_hash.update(data)
    return sha256_hash.hexdigest()

def encode_base64(iocs):
    message_bytes = iocs.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message


# Convert ip to rule, output base64 code of domain name to a file, create the rule contain ip rule and a dns rule.
# Input : file name, and the string that contain the first char of the rule for IP type.
def iocs_to_ids_rules(file_name, index_name):
    rule_str = "["
    my_file = open(fr"{vari['file']['list_iocs_folder']}/{file_name}", "r")
    res_rule_name = re.split(r"/", file_name)
    domain_encoded = open(f"{vari['file']['output_dir']}/encoded_{res_rule_name[0]}_{res_rule_name[1]}", "a")
    my_line = my_file.readlines()
    for i in range(0, len(my_line)):
        # print(my_line[i])
        elastic_res = search_iocs(my_line[i])
        if (bool(elastic_res['hits']['hits'])):
            continue
        else:
            if (check_type(my_line[i]) != "none"):
                add_iocs(index_name, my_line[i], check_type(my_line[i]), file_name)
                if (bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$", my_line[i]))) and (not re.match(r"^#", my_line[i])):
                    res = re.split(r":", my_line[i])
                    for k in range(0, 1):
                        ip_data = res[0]
                        port_data = res[1]
                        # print(f"{ip_data} and {port_data}")
                elif (bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", my_line[i]))) and (not re.match(r"^#", my_line[i])):
                    my_line[i] = str.rstrip(my_line[i])
                    rule_str += my_line[i]
                    rule_str += ","
                elif (bool(re.match(r".*\..*", my_line[i]))) and (not re.match(r"^#", my_line[i])):
                    print(encode_base64(my_line[i]), file=domain_encoded)
    rule_str = rule_str[:-1]
    rule_str += "]"
    outfile = open(f"{vari['file']['output_dir']}/{res_rule_name[0]}_{res_rule_name[1]}.rules", "w")
    print(f"alert any any -> any any (msg:\"ET DNS query for {file_name}\"; reference:url,https://github.com/stamparm/maltrail/blob/master/README.md; dns.query; dataset:set, {file_name}, type string, load: {file_name}.lst; sid:202025113; rev:1;))", file=outfile)
    if not bool(re.match(r"^]$", rule_str)):
        print(f"alert {rule_str} any -> any any (msg:\"something\")", file=outfile)
    rule_str = "["



def iocs_to_siem_rules():
    print("Do something")


# Run only in linux
def add_to_dataset(filename):
    for i in range(0, len(filename)):
        domain_encoded = open(f"{vari['file']['output_dir']}/encoded_{filename[i]}", "r")
        encode_dns = domain_encoded.readlines()
        number_of_elements = len(encode_dns)
        for j in range(0, number_of_elements):
            bash_command = ["dataset-add", {filename[i]}, "string", {encode_dns[j]}]
            process = subprocess.Popen(bash_command, stdout=subprocess.PIPE)
            output, error = process.communicate()


indices_body = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
            "iocs": { "type": "keyword" },
            "iocs_type": { "type": "keyword" },
            "campaign": { "type": "keyword" }
        }
    }
}


# file_name_old = open(r"D:\Downloads\file_name.txt", "r")
# list_file_name = file_name_old.readlines()
list_iocs_folder_name = [f for f in listdir(fr"{vari['file']['list_iocs_folder']}") if isdir(join(fr"{vari['file']['list_iocs_folder']}", f))]
elastic_client = init_connection(f"{vari['elastic_authen']['host']}", f"{vari['elastic_authen']['scheme']}",
                                 f"{vari['elastic_authen']['user']}", f"{vari['elastic_authen']['password']}", True, False)


repo_only_url = re.compile(r"^https:\/\/github.com\/[a-zA-Z0-9\-]*\/[a-zA-Z0-9\-]*$")

with open(vari['file']['list_url'], "r") as f:
    url_line = f.readlines()
    for i in range(0, len(url_line)):
        url_line[i] = str.strip(url_line[i])
        if bool(re.match(repo_only_url, url_line[i])):
            m = re.search("[a-zA-Z0-9\-]*$", url_line[i])
            if m:
                folder_name = m.group(0)

            if not os.path.isdir(fr"{vari['file']['list_iocs_folder']}/{folder_name}"):
                git.Git(f"{vari['file']['list_iocs_folder']}").clone(url_line[i])
            else:
                git.Git(fr"{vari['file']['list_iocs_folder']}/{folder_name}").pull()
        else:
            download(url_line[i], f"{vari['file']['list_iocs_folder']}", False)



def main():
    if check_indices(f"{vari['elastic_authen']['index_name']}"):
        print("indices exsists")
    else:
        print("Creating indices")
        create_index(f"{vari['elastic_authen']['index_name']}", indices_body)

    hash_file_path_new = open(fr"{vari['file']['new_hash']}", 'w')

    for k in range(0, len(list_iocs_folder_name)):
        list_iocs_file_name = [f for f in listdir(fr"{vari['file']['list_iocs_folder']}/{list_iocs_folder_name[k]}") if isfile(join(fr"{vari['file']['list_iocs_folder']}/{list_iocs_folder_name[k]}", f))]
        for i in range(0, len(list_iocs_file_name)):
            gen_hash = gen_hash_from_file(fr"{vari['file']['list_iocs_folder']}/{list_iocs_folder_name[k]}/{list_iocs_file_name[i]}")
            print(f"{list_iocs_folder_name[k]}/{list_iocs_file_name[i]} : {gen_hash}", file=hash_file_path_new)
        # hash_file_path_new.truncate(0)
    hash_file_path_new.close()

    if not os.path.isfile(fr"{vari['file']['old_hash']}"):
        hash_file_path = open(fr"{vari['file']['old_hash']}", 'w')
        for k in range(0, len(list_iocs_folder_name)):
            list_iocs_file_name = [f for f in listdir(fr"{vari['file']['list_iocs_folder']}/{list_iocs_folder_name[k]}") if isfile(join(fr"{vari['file']['list_iocs_folder']}/{list_iocs_folder_name[k]}", f))]
            for i in range(0, len(list_iocs_file_name)):
                gen_hash = gen_hash_from_file(fr"{vari['file']['list_iocs_folder']}/{list_iocs_folder_name[k]}/{list_iocs_file_name[i]}")
                print(f"{list_iocs_folder_name[k]}/{list_iocs_file_name[i]} : {gen_hash}", file=hash_file_path)
                #print(list_iocs_file_name[i])
                iocs_to_ids_rules(fr"{list_iocs_folder_name[k]}/{list_iocs_file_name[i]}", "iocs")
        # hash_file_path.close()
    else:
        my_res = list()
        hash_file_path = open(fr"{vari['file']['old_hash']}", 'r')
        hash_file_path_new = open(fr"{vari['file']['new_hash']}", 'r')
        my_line = hash_file_path.readlines()
        my_line_new = hash_file_path_new.readlines()
        for i in range(0, len(my_line)):
            my_line[i] = str.strip(my_line[i])
        for i in range(0, len(my_line_new)):
            for j in range(0, len(my_line_new) - len(my_line)):
                my_line.append("")
        for i in range(0, len(my_line_new)):
            my_line[i] = str.strip(my_line[i])
            my_line_new[i] = str.strip(my_line_new[i])
            if my_line[i] != my_line_new[i]:
                res = re.split("\s:\s", my_line_new[i])
                my_res.append(res[0])
        for i in range(0, len(my_res)):
            #print(my_res[i])
            iocs_to_ids_rules(my_res[i], "iocs")
        update_hash_file(fr"{vari['file']['old_hash']}", fr"{vari['file']['new_hash']}")



if __name__ == "__main__":
    main()
