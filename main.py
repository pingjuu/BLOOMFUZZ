from collections import OrderedDict
import json, sys
from optparse import OptionParser

from modules import *
from lib import *

from time import sleep


test_info = OrderedDict()
test_info["interface"] = "Bluetooth_L2CAP"
test_info["toolVer"] = "1.0.0"

def parse_option():
    parse = OptionParser('usage sudo python3 main.py -p <[pcapngfile]>')
    parse.add_option("-p", "--pcap", dest = "pcapng_file", help='./CommCapture/Airpod.pcapng')
    parse.add_option("-o", "--onetime", type=int, dest="onetime")
    # onetime : 1-terminate if crash occurs, 2-keep running even if crash occurs.
    (option, args) = parse.parse_args()
    return option.pcapng_file, option.onetime

if __name__== "__main__": 

    test_info, target_addr = bluetooth_classic_scan(test_info)

    while(1):
        test_info, target_service = bluetooth_services_and_protocols_search(target_addr, test_info)
        if target_service is False:
            print("Service not found on target device")
            sys.exit()
        target_protocol = target_service['protocol']
        target_profile = target_service['name']
        target_profile_port = target_service['port']

        if(target_protocol =="L2CAP"):
            break
        else:
            continue

    print("\n===================Test Informatoin===================")
    print(json.dumps(test_info, ensure_ascii=False, indent="\t"))
    print("======================================================\n")


    while True:
        try:
            sock = BluetoothL2CAPSocket(target_addr)
        except:
            pass
        else:
            break

    statemachine = L2CAP_StateMachine()
    # PreProcess
    statemachine, sock, dcid_value = SpecState_Pruning(target_addr, sock, target_profile_port, statemachine)
    CommCapture_Path, is_onetime = parse_option()
    capturedStateM = CommCapture(CommCapture_Path)

    Cluster_stateM = statemachine.Set_IsThere_Clustered_State(capturedStateM)

    print("[+] State Traveral & Communication Capture Result : {}".format(Cluster_stateM))

    # include captured packet
    test_info["StateMachine"] = Cluster_stateM
    test_info["packet"] = []

    # Mutation
    fuzzing(target_addr, target_profile, target_profile_port, statemachine, Cluster_stateM, test_info, dcid_value, is_onetime)
