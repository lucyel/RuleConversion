# TODO: download folder not from git
# TODO: check if donwloaded file is type acsii text, if is other type then not download.
# TODO: convert other iocs format: IP:PORT [done]

import re
import base64
import subprocess
import os
import hashlib
import urllib3
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from GitDownloader import download
from os import listdir
from os.path import isfile, join

urllib3.disable_warnings()


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


def init_hash_file(filehashgen, filename, folder_path):
    hash_file_path = open(f"{filehashgen}", "w")
    for i in range(0, len(filename)):
        gen_hash = gen_hash_from_file(f"{folder_path}\\{filename[i]}")
        print(f"{filename[i]} : {gen_hash}", file=hash_file_path)


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
# Input : a list type of file name, and the string that contain the first char of the rule for IP type.
def iocs_to_ids_rules(list_file_name, index_name):
    rule_str = "["
    for i in range(0, len(list_file_name)):
        my_file = open(f"D:\\Downloads\\test\\{list_file_name[i]}", "r")
        domain_encoded = open(f"D:\\Downloads\\res\\encoded_{list_file_name[i]}", "w")
        my_line = my_file.readlines()
        for j in range(0, len(my_line)):
            elastic_res = search_iocs(my_line[j])
            if (bool(elastic_res['hits']['hits'])):
                continue
            else:
                if (check_type(my_line[j]) != "none" ) :
                    add_iocs(index_name, my_line[j], check_type(my_line[j]), list_file_name[i])
                if (bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$", my_line[j]))) and (not re.match(r"^#", my_line[j])):
                    res = re.split(r":", my_line[j])
                    for k in range(0, 1):
                        ip_data = res[0]
                        port_data = res[1]
                        # print(f"{ip_data} and {port_data}")
                elif (bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", my_line[j]))) and (not re.match(r"^#", my_line[j])):
                    my_line[j] = str.rstrip(my_line[j])
                    rule_str += my_line[j]
                    rule_str += ","
                elif (bool(re.match(r".*\..*", my_line[j]))) and (not re.match(r"^#", my_line[j])):
                    print(encode_base64(my_line[j]), file=domain_encoded)
        rule_str = rule_str[:-1]
        rule_str += "]"
        outfile = open(f"D:\\Downloads\\res\\{list_file_name[i]}.rules", "w")
        print(
            f"alert any any -> any any (msg:\"ET DNS query for {list_file_name[i]}\"; reference:url,https://github.com/stamparm/maltrail/blob/master/README.md; dns.query; dataset:set, {list_file_name[i]}, type string, load: {list_file_name[i]}.lst; sid:202025113; rev:1;))",
            file=outfile)
        if not bool(re.match(r"^]$", rule_str)):
            print(f"alert {rule_str} any -> any any (msg:\"something\")", file=outfile)
        rule_str = "["
    # my_file.close()
    # domain_encoded.close()


def iocs_to_siem_rules():
    print("Do something")


# Run only in linux
def add_to_dataset(filename):
    for i in range(0, len(filename)):
        domain_encoded = open(f"D:\\Downloads\\res\\encoded_{filename[i]}", "r")
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


folder_path = r"D:\Downloads\test"
file_name_old = open(r"D:\Downloads\file_name.txt", "r")
list_file_name = file_name_old.readlines()
file_name = [f for f in listdir(folder_path) if isfile(join(folder_path, f))]
download_dirs = r"D:\Downloads\list_url.txt"
elastic_client = init_connection("192.168.252.131", "https", "elastic", "123456", True, False)
index_name="iocs"

with open(download_dirs, "r") as f:
    url_line = f.readlines()
    for i in range(0, len(url_line)):
        url_line[i] = str.strip(url_line[i])
        download(url_line[i], "D:\Downloads\download_test", False)

def main():
    if check_indices(index_name):
        print("indices exsists")
    else:
        print("Creating indices")
        create_index(index_name, indices_body)

    hash_file_path_new = open(r"D:\\Downloads\\res\\hash_file_new.txt", "w")
    for i in range(0, len(file_name)):
        gen_hash = gen_hash_from_file(f"D:\\Downloads\\test\\{file_name[i]}")
        print(f"{file_name[i]} : {gen_hash}", file=hash_file_path_new)

    if not os.path.isfile(r"D:\\Downloads\\res\\hash_file.txt"):
        init_hash_file(r"D:\\Downloads\\res\\hash_file.txt", file_name, folder_path)
        print(file_name)
        iocs_to_ids_rules(file_name, "iocs")
    else:
        my_res = list()
        hash_file_path = open(r"D:\\Downloads\\res\\hash_file.txt", "r")
        hash_file_path_new = open(r"D:\\Downloads\\res\\hash_file_new.txt", "r")
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
        print(my_res)
        iocs_to_ids_rules(my_res, "iocs")
        update_hash_file(r"D:\\Downloads\\res\\hash_file_new.txt", r"D:\\Downloads\\res\\hash_file.txt")


if __name__ == "__main__":
    main()
