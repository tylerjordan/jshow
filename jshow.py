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
    # Provide selection for sending a single command or multiple commands from a file
    if not my_ips:
        my_ips = chooseDevices(iplist_dir)
    command_list = []
    while True:
        command = raw_input("Enter an operational command: ")  # Change this to "input" when using Python 3
        if not command:
            break
        else:
            command_list.append(command)

    # Check if user wants to print output to a file
    log_file = None
    if getTFAnswer('\nPrint output to a file'):
        log_file = log_dir + "oper_cmd_" + datetime.datetime.now().strftime("%Y%m%d-%H%M") + ".log"
        print('Information logged in {0}'.format(log_file))

    output = ""
    screen_and_log(('User: {0}\n').format(creds["username"]), log_file)
    # Loop over commands and devices
    for ip in my_ips:
        if ping(ip):
            hostname = get_fact(ip, creds['username'], creds['password'], "hostname")
            screen_and_log('*' * 80 + '\n' + '[{0} at {1}]\n'.format(hostname, ip), log_file)
            for command in command_list:
                try:
                    results = op_command(ip, command, creds['username'], creds['password'])
                except Exception as err:
                    print("Error running op_command on {0} ERROR: {1}").format(ip, err)
                else:
                    screen_and_log(results + '\n', log_file)
                    # Append output to a variable, we'll save when done with output
                    if log_file:
                        output += results
        else:
            screen_and_log((("*" * 80) + "\nSkipping {0}, unable to ping.\n" + ("*" * 80) + "\n\n").format(ip), log_file)
    screen_and_log(("\n" + "*" * 30 + " Commands Completed " + "*" * 30 + "\n"), log_file)

    # Check if a file was requested, if so print output to file
    if log_file:
        try:
            f = open(log_file, 'w')
        except Exception as err:
            print "Problem writing to file {0} ERROR: {1}".format(log_file, err)
        else:
            f.write(output)
            print "Output Written To: {0}".format(log_file)
        f.close()

def populate_template(record, template_file):
    command_list = []
    new_command_list = []
    try:
        with open(template_file) as f:
            command_list = f.read().splitlines()
    except Exception as err:
        print "Error turning file into list. ERROR: {0}".format(err)
    else:
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

def template_commands(creds):
    # Option for creating dynamic configurations for dictionary of devices
    filelist = getFileList(config_dir)
    template_config = getOptionAnswer("Choose a config file", filelist)
    template_file = config_dir + template_config

    # Read template csv in as dictionary
    filelist = getFileList(csv_dir)
    csv_config = getOptionAnswer("Choose a csv file", filelist)
    csv_file = csv_dir + csv_config

    list_dict = csvListDict(csv_file)
    #for adict in list_dict:
    #    print adict

    # Create log file for operation
    log_file = log_dir + "set_cmd_" + datetime.datetime.now().strftime("%Y%m%d-%H%M") + ".log"
    print('\nInformation logged in {0}'.format(log_file))
    screen_and_log(('User: {0}\n').format(creds["username"]), log_file)
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


def standard_commands(creds, my_ips):
    # Provide option for using a file to supply configuration commands
    if not my_ips:
        my_ips = chooseDevices(iplist_dir)
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
            command = raw_input("Enter a set command: ")  # Change this to "input" when using Python 3
            if not command:
                break
            else:
                command_list.append(command)

    # Create log file for operation
    log_file = log_dir + "set_cmd_" + datetime.datetime.now().strftime("%Y%m%d-%H%M") + ".log"
    print('\nInformation logged in {0}'.format(log_file))
    screen_and_log(('User: {0}\n').format(creds["username"]), log_file)
    screen_and_log("*" * 50 + " COMMANDS " + "*" * 50 + '\n', log_file)
    for command in command_list:
        screen_and_log((" -> {0}\n".format(command)), log_file)

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
    my_options = ['Load IPs', 'Execute Operational Commands', 'Execute Set Commands', 'Execute Template Commands', 'Quit']
    my_ips = []

    # Get menu selection
    while True:
        print "*" * 50 + "\n"
        answer = getOptionAnswerIndex('Make a Selection', my_options)
        print "\n" + "*" * 50
        if answer == "1":
            my_ips = chooseDevices(iplist_dir)
        elif answer == "2":
            oper_commands(creds, my_ips)
        elif answer == "3":
            standard_commands(creds, my_ips)
        elif answer == "4":
            template_commands(creds)
        elif answer == "5":
            quit()