from scapy.packet import Packet
from scapy.all import *
from scapy.layers.bluetooth import BluetoothL2CAPSocket


# L2CAP State Name
L2CAP_CLOSED_STATE = 0x01
L2CAP_WAIT_CONNECT_STATE = 0x02
L2CAP_WAIT_CONNECT_RSP_STATE = 0x03
L2CAP_WAIT_CREATE_STATE = 0x04
L2CAP_WAIT_CREATE_RSP_STATE = 0x05
L2CAP_WAIT_CONFIG_STATE = 0x06
L2CAP_WAIT_SEND_CONFIG_STATE = 0x07
L2CAP_WAIT_CONFIG_RSP_STATE = 0x08
L2CAP_WAIT_CONFIG_REQ_RSP_STATE = 0x09
L2CAP_WAIT_CONFIG_REQ_STATE = 0x0A
L2CAP_WAIT_CONTROL_IND_STATE = 0x0B
L2CAP_WAIT_FINAL_RSP_STATE = 0x0C
L2CAP_WAIT_IND_FINAL_RSP_STATE = 0x0D
L2CAP_OPEN_STATE = 0x0E
L2CAP_WAIT_MOVE_CONFIRM_STATE = 0x0F
L2CAP_WAIT_MOVE_STATE = 0x10
L2CAP_WAIT_MOVE_RSP_STATE = 0x11
L2CAP_WAIT_CONFIRM_RSP_STATE = 0x12
L2CAP_WAIT_DISCONNECT_STATE = 0x13


def change_state2str(state):
    if state == L2CAP_CLOSED_STATE:
        return "Closed State"
    elif state == L2CAP_WAIT_CONNECT_STATE:
        return "Wait Connect State"
    elif state == L2CAP_WAIT_CONNECT_RSP_STATE:
        return "Wait Connect Rsp State"
    elif state == L2CAP_WAIT_CREATE_STATE:
        return "Wait Create State"
    elif state == L2CAP_WAIT_CREATE_RSP_STATE:
        return "Wait Create Rsp State"
    elif state == L2CAP_WAIT_CONFIG_STATE:
        return "Wait Config State"
    elif state == L2CAP_WAIT_SEND_CONFIG_STATE:
        return "Wait Send Config State"
    elif state == L2CAP_WAIT_CONFIG_RSP_STATE:
        return "Wait Config Rsp State"
    elif state == L2CAP_WAIT_CONFIG_REQ_RSP_STATE:
        return "Wait Config Req Rsp State"
    elif state == L2CAP_WAIT_CONFIG_REQ_STATE:
        return "Wait Config Req State"
    elif state == L2CAP_WAIT_CONTROL_IND_STATE:
        return "Wait Control Ind State"
    elif state == L2CAP_WAIT_FINAL_RSP_STATE:
        return "Wait Final Rsp State"
    elif state == L2CAP_WAIT_IND_FINAL_RSP_STATE:
        return "Wait Ind Final Rsp State"
    elif state == L2CAP_OPEN_STATE:
        return "Open State"
    elif state == L2CAP_WAIT_MOVE_CONFIRM_STATE:
        return "Wait Move Confirm State"
    elif state == L2CAP_WAIT_MOVE_STATE:
        return "Wait Move State"
    elif state == L2CAP_WAIT_MOVE_RSP_STATE:
        return "Wait Move Rsp State"
    elif state == L2CAP_WAIT_CONFIRM_RSP_STATE:
        return "Wait Confirm Rsp State"
    elif state == L2CAP_WAIT_DISCONNECT_STATE:
        return "Wait Disconnect State"
    else:
        print(f"State name : {state}")
        assert False, "Exception state exists"
 

# L2CAP Command Info
L2CAP_CMD_REJECT = 0x01
L2CAP_CMD_CONN_REQ = 0x02
L2CAP_CMD_CONN_RSP = 0x03
L2CAP_CMD_CONFIG_REQ = 0x04
L2CAP_CMD_CONFIG_RSP = 0x05
L2CAP_CMD_DISCONN_REQ = 0x06
L2CAP_CMD_DISCONN_RSP = 0x07
L2CAP_CMD_ECHO_REQ = 0x08
L2CAP_CMD_ECHO_RSP = 0X09
L2CAP_CMD_INFORM_REQ = 0X0A
L2CAP_CMD_INFORM_RSP = 0X0B
L2CAP_CMD_CREATE_CHANNEL_REQ = 0X0C
L2CAP_CMD_CREATE_CHANNEL_RSP = 0X0D
L2CAP_CMD_MOVE_CHANNEL_REQ = 0X0E
L2CAP_CMD_MOVE_CHANNEL_RSP = 0X0F
L2CAP_CMD_MOVE_CHANNEL_CONFIRM_REQ = 0X10
L2CAP_CMD_MOVE_CHANNEL_CONFIRM_RSP = 0X11
L2CAP_CMD_CONN_PARAM_UPDATE_REQ = 0X12
L2CAP_CMD_CONN_PARAM_UPDATE_RSP = 0X13
L2CAP_CMD_LE_CREDIT_BASED_CONN_REQ = 0X14
L2CAP_CMD_LE_CREDIT_BASED_CONN_RSP = 0X15
L2CAP_CMD_FLOW_CONTROL_CREDIT_IND = 0X16
L2CAP_CMD_CREDIT_BASED_CONN_REQ = 0X17
L2CAP_CMD_CREDIT_BASED_CONN_RSP = 0X18
L2CAP_CMD_CREDIT_BASED_RECONFIG_REQ = 0X19
L2CAP_CMD_CREDIT_BASED_RECONFIG_RSP = 0X1A


L2CAP_Connect_Result = {
	0: "Connection successful",
	1: "Connection pending",
	2: "Connection refused - PSM not supported",
	3: "Connection refused - seccurity block",
	4: "Connection refused - no resources available",
	6: "Connection refused - invalid Source CID",
	7: "Connection refused - Source CID already allocated",	
}


def send_pkt(bt_addr, sock, pkt):
    flag = True
    try:
        sock.send(pkt)
    except:
        flag = False
    # Reset Socket
    sock = BluetoothL2CAPSocket(bt_addr)
    return sock, flag

import signal
import time

class TimeOutException(Exception):
    pass

def alarm_handler(signum, frame):
    print("Time is up!")
    raise TimeOutException()

def recv_pkt(sock):
    flag = True
    try:
        conn_rsp = sock.recv()

    except Exception as e:
        flag = False
        conn_rsp = ""
       
    return conn_rsp, sock, flag

class new_L2CAP_ConnReq(Packet):
    name = "L2CAP Conn Req"
    fields_desc = [LEShortEnumField("psm", 0, {1: "SDP", 3: "RFCOMM", 5: "TCS-BIN", # noqa
                                               7: "TCS-BIN-CORDLESS", 15: "BNEP", 17: "HID-Control", # noqa
                                               19: "HID-Interrupt", 21: "UPnP", 23: "AVCTP-Control", # noqa
                                               25: "AVDTP", 27: "AVCTP-Browsing", 29: "UDI_C-Plane", # noqa
                                               31: "ATT", 33: "3DSP", 35: "IPSP", 37: "OTS"}), # noqa 
                   LEShortField("scid", 0),
                   ]
    
class new_L2CAP_ConnResp(Packet):
    name = "L2CAP Conn Resp"
    fields_desc = [LEShortField("dcid", 0),
                   LEShortField("scid", 0),
                   LEShortEnumField("result", 0, ["success", "pend", "cr_bad_psm", "cr_sec_block", "cr_no_mem", "reserved", "cr_inval_scid", "cr_scid_in_use"]),  # noqa: E501
                   LEShortEnumField("status", 0, ["no_info", "authen_pend", "author_pend", "reserved"]),  # noqa: E501
                   ]

class L2CAP_Create_Channel_Request(Packet):
    name = "L2CAP Create Channel Request"
    fields_desc = [LEShortEnumField("psm", 0, {1: "SDP", 3: "RFCOMM", 5: "TCS-BIN", # noqa
                                               7: "TCS-BIN-CORDLESS", 15: "BNEP", 17: "HID-Control", # noqa
                                               19: "HID-Interrupt", 21: "UPnP", 23: "AVCTP-Control", # noqa
                                               25: "AVDTP", 27: "AVCTP-Browsing", 29: "UDI_C-Plane", # noqa
                                               31: "ATT", 33: "3DSP", 35: "IPSP", 37: "OTS"}), # noqa 
                   LEShortField("scid", 0),
                   ByteField("controller_id", 0), 
                   ]

class L2CAP_Create_Channel_Response(Packet):
    name = "L2CAP Create Channel Response"
    fields_desc = [LEShortField("dcid", 0),
                   LEShortField("scid", 0), 
                   LEShortEnumField("result", 0, {0: "Connection successful", 1: "Connection pending", 2: "Connection refused - PSM not supported",
                                                  3: "Connection refused - security block", 4: "Connection refused - no resources available", 5: "Connection refused - Controller ID not supported",
                                                  6: "Connection refused - Invalid Source CID", 7: "Connection refused - Source CID already allocated"}),
                   LEShortEnumField("status", 0, {0: "No further information available", 1: "Authentication pending", 2: "Authorization pending"}), 
                   ]

class new_L2CAP_ConfReq(Packet):
    name = "L2CAP Conf Req"
    fields_desc = [ LEShortField("dcid",0),
                    LEShortField("flags",0),
                    ByteField("type",0),
                    ByteField("length",0),
                    ByteField("identifier",0),
                    ByteField("servicetype",0),
                    LEShortField("sdusize",0),
                    LEIntField("sduarrtime",0),
                    LEIntField("accesslat",0),
                    LEIntField("flushtime",0),
                    ]

class new_L2CAP_ConfResp(Packet):
    name = "L2CAP Conf Resp"
    fields_desc = [ LEShortField("scid",0),
                    LEShortField("flags",0),
                    LEShortField("result",0),
                    ByteField("type0",0),
                    ByteField("length0",0),
                    LEShortField("option0",0),
                    ByteField("type1",0),
                    ByteField("length1",0),  
                    ]

class L2CAP_Move_Channel_Request(Packet):
    name = "L2CAP Move Channel Request"
    fields_desc = [LEShortField("icid", 0),
                   ByteField("dest_controller_id", 0), 
                   ] # 0: move to Bluetooth BR/EDR, 1: move to wifi 802.11
    
class L2CAP_Move_Channel_Response(Packet):
    name = "L2CAP Move Channel Response"
    fields_desc = [LEShortField("icid", 0),
                   LEShortEnumField("result", 0, {0: "Move success", 1: "Move Pending",
                                                  2: "Move refused - Controller ID not supported",
                                                  3: "Move refused - new Controller ID is same as old Controller ID",
                                                  4: "Move refused - Configuration not supported",
                                                  5: "Move refused - Move Channel collision",
                                                  6: "Move refused - Channel not allowed to be moved"}), 
                   ] # 0: move to Bluetooth BR/EDR, 1: move to wifi 802.11
    
class L2CAP_Move_Channel_Confirmation_Request(Packet):
    name = "L2CAP Move Channel Confirmation Request"
    fields_desc = [LEShortField("icid", 0), 
                   LEShortEnumField("result", 0, {0: "Move success", 1: "Move failure"}), 
                   ]

class L2CAP_Move_Channel_Confirmation_Response(Packet):
    name = "L2CAP Move Channel Confirmation Response"
    fields_desc = [LEShortField("icid", 0), 
                    ]

class garbage_value(Packet):
	fields_desc = [
				   LEShortField("garbage", 0)
				   ]