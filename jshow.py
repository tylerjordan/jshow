# Author: Tyler Jordan
# File: jshow.py
# Last Modified: 2/2/2017
# Description: The purpose of this script is to execute commands on multiple Juniper devices. The script works in
# Windows, Linux, and Mac enviroments. This script can do bulk configuration pushes by using a CSV. When using the
# template feature, it is possible to push unique configurations to devices.
#   - execute operational commands on one or more Juniper devices
#   - execute edit commands on one or more Juniper devices
#   - execute a dynamic template on one or more Juniper devices

import platform
import subprocess
import getopt
import csv
import logging
import datetime
import pprint

from jnpr.junos import Device
from jnpr.junos.utils.sw import SW
from jnpr.junos.exception import *
from utility import *
from os.path import join
from getpass import getpass
from prettytable import PrettyTable
from Spinner import *

credsCSV = ""
username = ""
password = ""
ssh_port = 22

iplist_dir = ""
log_dir = ""
config_dir = ""
csv_dir = ""

system_slash = "/"   # This is the linux/mac slash format, windows format will be used in that case

remote_path = "/var/tmp"

def detect_env():
    """ Purpose: Detect OS and create appropriate path variables. """
    global credsCSV
    global iplist_dir
    global config_dir
    global log_dir
    global csv_dir
    global system_slash
    global ssh_port

    if platform.system().lower() == "windows":
        #print "Environment Windows!"
        credsCSV = ".\\pass.csv"
        iplist_dir = ".\\iplists\\"
        config_dir = ".\\configs\\"
        log_dir = ".\\logs\\"
        csv_dir = ".\\csv\\"
        system_slash = "\\"
    else:
        #print "Environment Linux/MAC!"
        credsCSV = "./pass.csv"
        iplist_dir = "./iplists/"
        config_dir = "./configs/"
        log_dir = "./logs/"
        csv_dir = "./csv/"


def oper_commands(creds, my_ips):
    print "*" * 50 + "\n" + " " * 10 + "OPERATIONAL COMMANDS MENU\n" + "*" * 50
    # Provide selection for sending a single command or multiple commands from a file
    if not my_ips:
        my_ips = chooseDevices(iplist_dir)
    if my_ips:
        command_list = []
        print "\n" + "*" * 50 + "\n"
        while True:
            command = raw_input("Enter an operational command: ")  # Change this to "input" when using Python 3
            if not command:
                break
            else:
                command_list.append(command)

        if getTFAnswer("Continue with template deployment?"):
            # Check if user wants to print output to a file
            log_file = None
            now = datetime.datetime.now()
            if getTFAnswer('Print output to a file'):
                log_file = log_dir + "oper_cmd_" + now.strftime("%Y%m%d-%H%M") + ".log"
                print('Information logged in {0}'.format(log_file))

            # Header of operational command output
            screen_and_log("*" * 50 + "\n" + " " * 10 + "OPERATIONAL COMMANDS OUTPUT\n" + "*" * 50 + "\n", log_file)
            screen_and_log(('User: {0}\n').format(creds["username"]), log_file)
            screen_and_log(('Performed: {0}\n').format(now), log_file)
            screen_and_log('*' * 50 + '\n' + " " * 10 + "COMMANDS EXECUTED\n" + "*" * 50 + '\n', log_file)
            for command in command_list:
                screen_and_log(' -> {0}\n'.format(command), log_file)
            screen_and_log('*' * 50 + '\n\n', log_file)

            # Loop over commands and devices
            devs_accessed = 0
            devs_unreachable = 0
            loop = 0
            for ip in my_ips:
                loop += 1
                if ping(ip):
                    devs_accessed += 1
                    hostname = get_fact(ip, creds['username'], creds['password'], "hostname")
                    screen_and_log('*' * 80 + '\n', log_file)
                    screen_and_log('[{0} at {1}]'.format(hostname, ip), log_file)
                    screen_and_log(' ({0} of {1})\n'.format(loop, len(my_ips)), log_file)
                    for command in command_list:
                        try:
                            results = op_command(ip, command, creds['username'], creds['password'])
                        except Exception as err:
                            print("Error running op_command on {0} ERROR: {1}").format(ip, err)
                        else:
                            screen_and_log(results + '\n', log_file)
                else:
                    screen_and_log("*" * 80 + "\n", log_file)
                    screen_and_log("Unable to ping {0}, skipping. ({1} of {2})\n".format(ip, str(loop), len(my_ips)), log_file)
                    screen_and_log("*" * 80 + "\n\n", log_file)
                    devs_unreachable += 1
            screen_and_log(("*" * 30 + " Commands Completed " + "*" * 30 + "\n\n"), log_file)

            # Results of commands
            screen_and_log("Total Devices:       {0}\n".format(len(my_ips)), log_file)
            screen_and_log("Devices Accessed:    {0}\n".format(devs_accessed), log_file)
            screen_and_log("Devices Unreachable: {0}\n\n".format(devs_unreachable), log_file)
            screen_and_log('*' * 80 + '\n\n', log_file)

        else:
            print "\n!!! Configuration deployment aborted... No changes made !!!\n"

# Adds device specific content to a template file
def populate_template(record, template_file):
    command_list = txt_to_list(template_file)
    new_command_list = []
    if command_list:
        # Loop over commands
        for command in command_list:
            #print("Command: {0}").format(command)
            if not re.match(r'^\s*$', command):
                if re.match(r'.*\{\{.*\}\}.*', command):
                    #print("Template Command: {0}").format(command)
                    matches = re.findall(r"\{\{.*?\}\}", command)
                    #print("Template Matches: {0}").format(matches)
                    for match in matches:
                        term = match[3:-3]
                        vareg = r"{{ " + term + " }}"
                        #print "Var regex: {0}".format(vareg)
                        command = re.sub(vareg, record[term], command)
                        #print "New String: {0}".format(command)
                #else:
                    #print("Standard Command: {0}").format(command)
            new_command_list.append(command)
    return new_command_list

# Template function for bulk set command deployment
def template_commands(creds):
    print "*" * 50 + "\n" + " " * 10 + "TEMPLATE COMMANDS MENU\n" + "*" * 50

    # Choose the template configuration file to use
    filelist = getFileList(config_dir)
    template_config = getOptionAnswer("Choose a template config file", filelist)
    print "-" * 50
    template_file = config_dir + template_config
    print " " * 10 + "File: " + template_config
    print "-" * 50
    # Display the commands in the configuration file
    for line in txt_to_list(template_file):
        print " -> {0}".format(line)
    print "-" * 50

    # Choose the template csv file to use
    filelist = getFileList(csv_dir)
    csv_config = getOptionAnswer("Choose a template csv file", filelist)
    csv_file = csv_dir + csv_config
    list_dict = csvListDict(csv_file)
    print " " * 10 + "File: " + csv_config
    print "-" * 50

    # Capture the headers of the CSV file
    with open(csv_file, 'r') as f:
        first_line = f.readline().strip()
    keys = first_line.split(',')

    # Sort headers with mgmt_ip being the first key
    sorted_keys = []
    sorted_keys.append('mgmt_ip')
    for one_key in keys:
        if one_key != 'mgmt_ip':
            sorted_keys.append(one_key)

    # Print the CSV file and the
    for device in list_dict:
        for key in sorted_keys:
            if key == 'mgmt_ip':
                print " -> {0}".format(device[key])
            else:
                print " ---> {0}: {1}".format(key, device[key])
    print "-" * 50
    print "Total IPs: {0}".format(len(list_dict))

    if getTFAnswer("Continue with template deployment?"):
        # Create log file for operation
        now = datetime.datetime.now()
        log_file = log_dir + "set_cmd_" + now.strftime("%Y%m%d-%H%M") + ".log"
        print('\nInformation logged in {0}'.format(log_file))

        # Print output header, for both screen and log outputs
        screen_and_log("*" * 50 + "\n" + " " * 10 + "TEMPLATE COMMANDS OUTPUT\n" + "*" * 50 + "\n", log_file)
        screen_and_log(('User: {0}\n').format(creds["username"]), log_file)
        screen_and_log(('Performed: {0}\n').format(now), log_file)
        screen_and_log('*' * 50 + '\n' + " " * 10 + "COMMANDS TO EXECUTE\n" + "*" * 50 + '\n', log_file)
        for line in txt_to_list(template_file):
            screen_and_log(" -> {0}\n".format(line), log_file)
        screen_and_log("*" * 50 + "\n\n", log_file)

        # Try to load configurations onto defined devices
        screen_and_log("-" * 49 + " START LOAD " + "-" * 49 + '\n', log_file)

        for record in list_dict:
            if ping(record['mgmt_ip']):
                hostname = get_fact(record['mgmt_ip'], creds["username"], creds["password"], "hostname")
                if not hostname:
                    hostname = "Unknown"
                screen_and_log("*" * 5 + " " + hostname + " at (" + record["mgmt_ip"] + ") " + "*" * 5 + '\n', log_file)
                screen_and_log("-" * 50 + " COMMANDS " + "-" * 50 + '\n', log_file)
                command_list = populate_template(record, template_file)
                for command in command_list:
                    screen_and_log((" -> {0}\n".format(command)), log_file)
                screen_and_log("-" * 110 + '\n', log_file)
                try:
                    screen_and_log("-" * 50 + " EXECUTE " + "-" * 51 + '\n\n', log_file)
                    set_command(record['mgmt_ip'], creds["username"], creds["password"], ssh_port, log_file, command_list)
                    screen_and_log("\n" + ("-" * 110) + '\n\n', log_file)
                except Exception as err:
                    print "Problem changing configuration ERROR: {0}".format(err)
            else:
                screen_and_log("-" * 110 + '\n', log_file)
                screen_and_log("Skipping {0}, unable to ping.\n".format(record['mgmt_ip']), log_file)
                screen_and_log("-" * 110 + '\n\n', log_file)

        screen_and_log("-" * 50 + " END LOAD " + "-" * 50 + '\n\n', log_file)
    else:
        print "\n!!! Configuration deployment aborted... No changes made !!!\n"

# Function to push set commands to multiple devices
def standard_commands(creds, my_ips):
    # Provide option for using a file to supply configuration commands
    if not my_ips:
        my_ips = chooseDevices(iplist_dir)
    if my_ips:
        command_list = []
        if getTFAnswer('\nProvide commands from a file'):
            filelist = getFileList(config_dir)
            # If the files exist...
            if filelist:
                config_file = getOptionAnswer("Choose a config file", filelist)
                config_file = config_dir + config_file
                with open(config_file) as f:
                    command_list = f.read().splitlines()
        else:
            # Provide selection for sending a single set command or multiple set commands
            while True:
                print "\n" + "*" * 50 + "\n"
                command = raw_input("Enter a set command: ")  # Change this to "input" when using Python 3
                if not command:
                    break
                else:
                    command_list.append(command)

        # Create log file for operation
        log_file = log_dir + "set_cmd_" + datetime.datetime.now().strftime("%Y%m%d-%H%M") + ".log"

        # Print output header, for both screen and log outputs
        screen_and_log("*" * 50 + "\n" + " " * 10 + "TEMPLATE COMMANDS OUTPUT\n" + "*" * 50 + "\n", log_file)
        screen_and_log(('User: {0}\n').format(creds["username"]), log_file)
        screen_and_log(('Performed: {0}\n').format(now), log_file)
        screen_and_log('*' * 50 + '\n' + " " * 10 + "COMMANDS TO EXECUTE\n" + "*" * 50 + '\n', log_file)
        for line in txt_to_list(template_file):
            screen_and_log(" -> {0}\n".format(line), log_file)
        screen_and_log("*" * 50 + "\n\n", log_file)

        # Loop over all devices in the rack
        screen_and_log("*" * 50 + " START LOAD " + "*" * 50 + '\n', log_file)
        for ip in my_ips:
            if ping(ip):
                try:
                    set_command(ip, creds["username"], creds["password"], ssh_port, log_file, command_list)
                except Exception as err:
                    print "Problem changing configuration ERROR: {0}".format(err)
            else:
                screen_and_log("Skipping {0}, unable to ping.\n", log_file)

        screen_and_log("*" * 50 + " END LOAD " + "*" * 50 + '\n', log_file)

# Function to exit program
def quit():
    print("Thank you for using JRack. Powered by electricity!")
    sys.exit(0)

# Main execution loop
if __name__ == "__main__":

    # Detect the platform type
    detect_env()
    # Get credentials from file
    creds = csv_to_dict(credsCSV)

    # Define menu options
    my_options = ['Execute Operational Commands', 'Execute Set Commands', 'Execute Template Commands', 'Quit']
    my_ips = []

    # Get menu selection
    while True:
        print "*" * 50 + "\n" + " " * 10 + "JSHOW MAIN MENU\n" + "*" * 50
        answer = getOptionAnswerIndex('Make a Selection', my_options)
        if answer == "1":
            oper_commands(creds, my_ips)
        elif answer == "2":
            standard_commands(creds, my_ips)
        elif answer == "3":
            template_commands(creds)
        elif answer == "4":
            quit()