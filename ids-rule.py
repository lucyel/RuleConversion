# TODO: compare 2 iocs file to check if it is skipable
# TODO: download folder not from git
# TODO: check if donwloaded file is type acsii text, if is other type then not download.
# TODO: convert other iocs format: IP:PORT [done]

import re
import base64
import subprocess
import os
import hashlib
from os import listdir
from os.path import isfile, join

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


def download_from_git(git_url, return_path):
    print("do something")


def download_from_other(url, return_path):
    print("do something")


# Convert ip to rule, output base64 code of domain name to a file, create the rule contain ip rule and a dns rule.
# Input : a list type of file name, and the string that contain the first char of the rule for IP type.
def iocs_to_ids_rules(list_file_name):
    rule_str = "["
    for i in range(0, len(list_file_name)):
        my_file = open(f"D:\\Downloads\\test\\{list_file_name[i]}", "r")
        domain_encoded = open(f"D:\\Downloads\\res\\encoded_{list_file_name[i]}", "w")
        my_line = my_file.readlines()
        for j in range(0, len(my_line)):
            if (bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$", my_line[j]))) and (not re.match(r"^#", my_line[j])):
                res = re.split(r":", my_line[j])
                for k in range(0, 1):
                    ip_data = res[0]
                    port_data = res[1]
                    # print(f"{ip_data} and {port_data}")
            if (bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", my_line[j]))) and (not re.match(r"^#", my_line[j])):
                my_line[j] = str.rstrip(my_line[j])
                rule_str += my_line[j]
                rule_str += ","
            elif (bool(re.match(r".*\..*", my_line[j]))) and (not re.match(r"^#", my_line[j])):
                message_bytes = my_line[j].encode('ascii')
                base64_bytes = base64.b64encode(message_bytes)
                base64_message = base64_bytes.decode('ascii')
                print(base64_message, file=domain_encoded)
        rule_str = rule_str[:-1]
        rule_str += "]"
        outfile = open(f"D:\\Downloads\\res\\{list_file_name[i]}.rules", "w")
        print(
            f"alert any any -> any any (msg:\"ET DNS query for {list_file_name[i]}\"; reference:url,https://github.com/stamparm/maltrail/blob/master/README.md; dns.query; dataset:set, {list_file_name[i]}, type string, load: {list_file_name[i]}.lst; sid:202025113; rev:1;))",
            file=outfile)
        if not bool(re.match(r"^]$", rule_str)):
            print(f"alert {rule_str} any -> any any (msg:\"something\")", file=outfile)
        rule_str = "["
    my_file.close()
    domain_encoded.close()


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



folder_path = r"D:\Downloads\test"
file_name = [f for f in listdir(folder_path) if isfile(join(folder_path, f))]


hash_file_path_new = open(r"D:\\Downloads\\res\\hash_file_new.txt", "w")
for i in range(0, len(file_name)):
    gen_hash = gen_hash_from_file(f"D:\\Downloads\\test\\{file_name[i]}")
    print(f"{file_name[i]} : {gen_hash}", file=hash_file_path_new)

if not os.path.isfile(r"D:\\Downloads\\res\\hash_file.txt"):
    hash_file_path = open(r"D:\\Downloads\\res\\hash_file.txt", "w")
    for i in range(0, len(file_name)):
        gen_hash = gen_hash_from_file(f"D:\\Downloads\\test\\{file_name[i]}")
        print(f"{file_name[i]} : {gen_hash}", file=hash_file_path)
    #iocs_to_ids_rules(file_name)
else:
    my_res = list()
    hash_file_path = open(r"D:\\Downloads\\res\\hash_file.txt", "r")
    hash_file_path_new = open(r"D:\\Downloads\\res\\hash_file_new.txt", "r")
    my_line = hash_file_path.readlines()
    my_line_new = hash_file_path_new.readlines()
    for i in range(0, len(my_line)):
        my_line[i] = str.strip(my_line[i])
        my_line_new[i] = str.strip(my_line_new[i])
        if my_line[i] != my_line_new[i]:
            res = re.split("\s:\s", my_line[i])
            my_res.append(res[0])
    print(my_res)
    #iocs_to_ids_rules(my_res)
