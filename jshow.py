# Author: Tyler Jordan
# File: jshow.py
# Last Modified: 1/27/2017
# Description: main execution file, starts the top-level menu

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

credsCSV = ""
username = ""
password = ""
ssh_port = 22

iplist_dir = ""
log_dir = ""
config_dir = ""

system_slash = "/"   # This is the linux/mac slash format, windows format will be used in that case

remote_path = "/var/tmp"

def detect_env():
    """ Purpose: Detect OS and create appropriate path variables. """
    global credsCSV
    global iplist_dir
    global config_dir
    global log_dir
    global system_slash
    global ssh_port

    if platform.system().lower() == "windows":
        #print "Environment Windows!"
        credsCSV = ".\\pass.csv"
        iplist_dir = ".\\iplists\\"
        config_dir = ".\\configs\\"
        log_dir = ".\\logs\\"
        system_slash = "\\"
    else:
        #print "Environment Linux/MAC!"
        credsCSV = "./pass.csv"
        iplist_dir = "./iplists/"
        config_dir = "./configs/"
        log_dir = "./logs/"

def oper_commands(creds, my_ips):
    # Provide selection for sending a single command or multiple commands from a file
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


def template_commands(creds):
    # Option for creating dynamic configurations for dictionary of devices
    filelist = getFileList(config_dir)
    template_config = getOptionAnswer("Choose a config file", filelist)
    template_file = config_dir + template_config

    command_list = []
    with open(template_file) as f:
        command_list = f.read().splitlines()

    for command in command_list:
        if not re.match(r'^\s*$', command):
            if re.match(r'\{\{', command):
                print("Command: {0}").format(command)



def set_commands(creds, my_ips):
    # Provide option for using a file to supply configuration commands
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
    detect_env()
    creds = csv_to_dict(credsCSV)
    #myuser = creds['username']
    #mypwd = creds['password']

    my_options = ['Load IPs', 'Execute Operational Commands', 'Execute Set Commands', 'Template Commands', 'Quit']
    my_ips = []

    while True:
        print "*" * 50 + "\n"
        answer = getOptionAnswerIndex('Make a Selection', my_options)
        print "\n" + "*" * 50
        if answer == "1":
            my_ips = chooseDevices(iplist_dir)
        elif answer == "2":
            oper_commands(creds, my_ips)
        elif answer == "3":
            set_commands(creds, my_ips)
        elif answer == "4":
            template_commands(creds)
        elif answer == "5":
            quit()