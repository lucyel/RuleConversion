#TODO: delete the file with rule that has no ip iocs
#TODO: compare 2 iocs file to check if it is skipable

import re
import base64
import subprocess
from os import listdir
from os.path import isfile, join

output_rule = open("D:\Downloads\output_file.txt", "a")
my_str = "["
folder_path = r"D:\Downloads\test"
file_name = [f for f in listdir(folder_path) if isfile(join(folder_path, f))]

number_of_folder = len(file_name)

for i in range(0, number_of_folder):
    my_file = open(f"D:\Downloads\\test\{file_name[i]}", "r")
    domain_encoded = open(f"D:\Downloads\encoded_{file_name[i]}", "w")
    my_line = my_file.readlines()
    # print(my_line)
    number_of_elements = len(my_line)
    for j in range(0, number_of_elements):
        ignored_data = re.search("^#", my_line[j])
        is_ignored = bool(ignored_data)
        matched_data_IP = re.search("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", my_line[j])
        is_matched_IP = bool(matched_data_IP)
        matched_data_domain = re.search(".*\..*", my_line[j])
        is_matched_domain = bool(matched_data_domain)
        if ((is_matched_IP == True) and (is_ignored == False)):
            my_line[j] = str.rstrip(my_line[j])
            my_str += my_line[j]
            my_str += ","
        elif ((is_matched_domain == True) and (is_ignored == False)):
            message_bytes = my_line[j].encode('ascii')
            base64_bytes = base64.b64encode(message_bytes)
            base64_message = base64_bytes.decode('ascii')
            print(base64_message, file = domain_encoded)
    my_str = my_str[:-1]
    my_str += "]"
    outfile = open(f"D:\Downloads\{file_name[i]}.rules", "w")
    print(f"alert any any -> any any (msg:\"ET DNS query for {file_name[i]}\"; reference:url,https://github.com/Xanderux/suricata_CTI/blob/main/README.md; dns.query; dataset:set, {file_name[i]}, type string, load: {file_name[i]}.lst; sid:202025113; rev:1;))", file=outfile)
    print(f"alert {my_str} any -> any any (msg:\"something\")", file = outfile)
    my_str = "["


#Run only in linux
for i in range(0, number_of_folder):
    domain_encoded = open(f"D:\Downloads\encoded_{file_name[i]}", "r")
    encode_dns = domain_encoded.readlines()
    number_of_elements = len(encode_dns)
    for j in range(0, number_of_elements):
        bash_command = ["dataset-add", {file_name[i]}, "string", {encode_dns[j]}]
        process = subprocess.Popen(bash_command, stdout=subprocess.PIPE)
        output, error = process.communicate()

# for path in file_path:
#     with open(path, 'r') as f:
#         file = f.readlines()
#         all_files.append(file)
#
# number_of_folder = len(all_files)
#
#
# for i in range(0, number_of_folder):
#     number_of_elements = len(all_files[i])
#     for j in range(0, number_of_elements):
#         ignored_data = re.search("^#", all_files[i][j])
#         is_ignored = bool(ignored_data)
#         matched_data_IP = re.search("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", all_files[i][j])
#         is_matched_IP = bool(matched_data_IP)
#         matched_data_domain = re.search(".*\..*", all_files[i][j])
#         is_matched_domain = bool(matched_data_domain)
#         if ((is_matched_IP == True) and (is_ignored == False)):
#             all_files[i][j] = str.rstrip(all_files[i][j])
#             my_str += all_files[i][j]
#             my_str += ","
#         elif ((is_matched_domain == True) and (is_ignored == False)):
#             message_bytes = all_files[i][j].encode('ascii')
#             base64_bytes = base64.b64encode(message_bytes)
#             base64_message = base64_bytes.decode('ascii')
#             print(base64_message, file = domain_encoded)

#my_file.close()
output_rule.close()
my_file.close()
domain_encoded.close()
