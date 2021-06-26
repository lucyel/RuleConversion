# TODO: delete the file with rule that has no ip iocs
# TODO: compare 2 iocs file to check if it is skipable
# TODO: download folder not from git

import re
import base64
import subprocess
from hash_gen import gen_hash_from_file
from os import listdir
from os.path import isfile, join


def iocs_to_ids_rules(filename, mystr):
    for i in range(0, len(filename)):
        my_file = open(f"D:\\Downloads\\test\\{filename[i]}", "r")
        domain_encoded = open(f"D:\\Downloads\\encoded_{filename[i]}", "w")
        my_line = my_file.readlines()
        for j in range(0, len(my_line)):
            if (bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", my_line[j]))) and (
            not re.match(r"^#", my_line[j])):
                my_line[j] = str.rstrip(my_line[j])
                mystr += my_line[j]
                mystr += ","
            elif (bool(re.match(r".*\..*", my_line[j]))) and (not re.match(r"^#", my_line[j])):
                message_bytes = my_line[j].encode('ascii')
                base64_bytes = base64.b64encode(message_bytes)
                base64_message = base64_bytes.decode('ascii')
                print(base64_message, file=domain_encoded)
        mystr = mystr[:-1]
        mystr += "]"
        outfile = open(f"D:\\Downloads\\{filename[i]}.rules", "w")
        print(
            f"alert any any -> any any (msg:\"ET DNS query for {filename[i]}\"; reference:url,https://github.com/stamparm/maltrail/blob/master/README.md; dns.query; dataset:set, {filename[i]}, type string, load: {filename[i]}.lst; sid:202025113; rev:1;))",
            file=outfile)
        if not bool(re.match(r"^]$", mystr)):
            print(f"alert {mystr} any -> any any (msg:\"something\")", file=outfile)
        mystr = "["
    my_file.close()
    domain_encoded.close()


def iocs_to_siem_rules():
    print("Do something")


# Run only in linux
def add_to_dataset(filename):
    for i in range(0, len(filename)):
        domain_encoded = open(f"D:\\Downloads\\encoded_{filename[i]}", "r")
        encode_dns = domain_encoded.readlines()
        number_of_elements = len(encode_dns)
        for j in range(0, number_of_elements):
            bash_command = ["dataset-add", {filename[i]}, "string", {encode_dns[j]}]
            process = subprocess.Popen(bash_command, stdout=subprocess.PIPE)
            output, error = process.communicate()


my_str = "["
folder_path = r"D:\Downloads\test"
file_name = [f for f in listdir(folder_path) if isfile(join(folder_path, f))]


iocs_to_ids_rules(file_name, my_str)
