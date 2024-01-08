import time
from random import randint
from datetime import date, datetime
from collections import OrderedDict
from scapy.layers.bluetooth import *

from modules.logger import *
from modules.PreProcess import *
from lib import * 
import traceback

now = datetime.now()
t = str(now)[11:19].replace(':',"",2)
today = date.today()
today = today.isoformat()
d = today[2:4] + today[5:7] + today[8:10]

def get_logtime():
    global d
    global t
    return d+t

logger = Logger(get_logtime())


pkt_cnt = 0
crash_cnt = 0
conn_rsp_flag = 0
ITER = 2500


def fuz_send_pkt(bt_addr, sock, pkt, cmd_code, state):
    """
    Errno
        ConnectionResetError: [Errno 104] Connection reset by peer
        ConnectionRefusedError: [Errno 111] Connection refused
        TimeoutError: [Errno 110] Connection timed out 
        and so on ..
    """
    global crash_cnt
    global pkt_cnt
    pkt_cnt += 1

    
    pkt_info = ""
    is_crashed = False
    try:
        sock.send(pkt)
        # print(pkt.summary)
        pkt_info = {}
        pkt_info["no"] = pkt_cnt
        pkt_info["protocol"] = "L2CAP"
        pkt_info["sended_time"] = str(datetime.now())
        pkt_info["payload"] = log_pkt(pkt)
        pkt_info["crash"] = "n"
        pkt_info["l2cap_state"] = state

    except ConnectionResetError:
        print("[-] Crash Found - ConnectionResetError detected")
        if(l2ping(bt_addr) == False):
            print("Crash Packet :", pkt)

            crash_cnt += 1
            logger.Q_crash_cnt += 1
            print("Crash packet count : ", crash_cnt)
            pkt_info = {}
            pkt_info["no"] = pkt_cnt
            pkt_info["protocol"] = "L2CAP"
            pkt_info["sended_time"] = str(datetime.now())
            pkt_info["cmd"] = cmd_code
            pkt_info["payload"] = log_pkt(pkt)
            pkt_info["l2cap_state"] = state
            pkt_info["sended?"] = "n"			
            pkt_info["crash"] = "y"
            pkt_info["crash_info"] = "ConnectionResetError"
            is_crashed = True

    except ConnectionRefusedError:
        print("[-] Crash Found - ConnectionRefusedError detected")
        if(l2ping(bt_addr) == False):
            print("Crash Packet :", pkt)
            crash_cnt += 1

            logger.Q_crash_cnt += 1
            print("Crash packet count : ", crash_cnt)
            pkt_info = {}
            pkt_info["no"] = pkt_cnt
            pkt_info["protocol"] = "L2CAP"
            pkt_info["sended_time"] = str(datetime.now())
            pkt_info["cmd"] = cmd_code
            pkt_info["payload"] = log_pkt(pkt)
            pkt_info["l2cap_state"] = state			
            pkt_info["sended?"] = "n"			
            pkt_info["crash"] = "y"
            pkt_info["crash_info"] = "ConnectionRefusedError"
            is_crashed = True

    except ConnectionAbortedError:
        print("[-] Crash Found - ConnectionAbortedError detected")
        if(l2ping(bt_addr) == False):
            print("Crash Packet :", pkt)
            crash_cnt += 1

            logger.Q_crash_cnt += 1
            print("Crash packet count : ", crash_cnt)
            pkt_info = {}
            pkt_info["no"] = pkt_cnt
            pkt_info["protocol"] = "L2CAP"
            pkt_info["sended_time"] = str(datetime.now())
            pkt_info["cmd"] = cmd_code
            pkt_info["payload"] = log_pkt(pkt)
            pkt_info["l2cap_state"] = state			
            pkt_info["sended?"] = "n"			
            pkt_info["crash"] = "y"
            pkt_info["crash_info"] = "ConnectionAbortedError"		
            is_crashed = True

    except TimeoutError:
        # State Timeout
        print("[-] Crash Found - TimeoutError detected")
        print("Crash Packet :", pkt)
        crash_cnt += 1

        logger.Q_crash_cnt += 1
        print("Crash packet count : ", crash_cnt)
        pkt_info = {}
        pkt_info["no"] = pkt_cnt
        pkt_info["protocol"] = "L2CAP"
        pkt_info["sended_time"] = str(datetime.now())
        pkt_info["cmd"] = cmd_code
        pkt_info["payload"] = log_pkt(pkt)
        pkt_info["l2cap_state"] = state
        pkt_info["sended?"] = "n"			
        pkt_info["crash"] = "y"
        pkt_info["crash_info"] = "TimeoutError"
        is_crashed = True

    except OSError as e:
        """
        OSError: [Errno 107] Transport endpoint is not connected
        OSError: [Errno 112] Host is down
        """
        if "Host is down" in e.__doc__:
            print("[-] Crash Found - Host is down")
            print("Crash Packet :", pkt)
            crash_cnt += 1
            
            logger.Q_crash_cnt += 1
            print("Crash packet count : ", crash_cnt)
            pkt_info = {}
            pkt_info["no"] = pkt_cnt
            pkt_info["protocol"] = "L2CAP"
            pkt_info["sended_time"] = str(datetime.now())
            pkt_info["cmd"] = cmd_code
            pkt_info["payload"] = log_pkt(pkt)
            pkt_info["l2cap_state"] = state
            pkt_info["sended?"] = "n"
            pkt_info["crash"] = "y"
            pkt_info["DoS"] = "y"
            pkt_info["crash_info"] = "OSError - Host is down"
            print("[-] Crash packet causes HOST DOWN. Test finished.")
            is_crashed = True
    else: pass

    if(pkt_info == ""): pass
    else: logger.inputQueue(pkt_info)
	# Reset Socket
    try:
        sock = BluetoothL2CAPSocket(bt_addr)
    except: pass
    
    return sock, is_crashed


def GetMPacket(cmd_code):
    # [code id] which can be occured in each section
    if cmd_code == L2CAP_CMD_CONN_REQ:
        p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConnReq(psm=0)
    elif cmd_code == L2CAP_CMD_CONN_RSP:
        p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConnResp()
    elif cmd_code == L2CAP_CMD_CREATE_CHANNEL_REQ:
        p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Create_Channel_Request(psm=0)
    elif cmd_code == L2CAP_CMD_CREATE_CHANNEL_RSP:
        p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Create_Channel_Response()
    elif cmd_code == L2CAP_CMD_CONFIG_REQ:
        p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfReq()
    elif cmd_code == L2CAP_CMD_CONFIG_RSP:
        p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfResp()
    elif cmd_code == L2CAP_CMD_MOVE_CHANNEL_REQ:
        p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Request(dest_controller_id=0)
    elif cmd_code == L2CAP_CMD_MOVE_CHANNEL_RSP:
        p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Response(icid=0x00)
    elif cmd_code == L2CAP_CMD_MOVE_CHANNEL_CONFIRM_REQ:
        p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Confirmation_Request(icid=0x00)
    elif cmd_code == L2CAP_CMD_MOVE_CHANNEL_CONFIRM_RSP:
        p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Confirmation_Response(icid=0x00)
    elif cmd_code == L2CAP_CMD_DISCONN_REQ:
        p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_DisconnReq()
    elif cmd_code == L2CAP_CMD_DISCONN_RSP:
        p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_DisconnResp()
    else:
        print("command code : ", cmd_code)
    pkt = Mutate_Packet(cmd_code, p)
    return pkt

@timeout(1)
def Check_TargetTrace(sock):    # Check if target state of fuzzer and current state of target device is located in same cluster.
    conn_rsp, sock, _ = recv_pkt(sock)
    if conn_rsp == "": return False
    elif conn_rsp.code == L2CAP_CMD_REJECT : return True 
    else: return False

def GotoClosedState(bt_addr, statemachine, sock, dcid_value):
    pkt = L2CAP_CmdHdr(code=L2CAP_CMD_DISCONN_REQ)/L2CAP_DisconnReq(scid=OUR_LOCAL_SCID, dcid=dcid_value)
    sock, _ = fuz_send_pkt(bt_addr, sock, pkt, L2CAP_CMD_DISCONN_REQ, statemachine.CURRENT_STATE)
    statemachine.CURRENT_STATE = "Closed State"

    
def creation_state_fuzzing(bt_addr, sock, statemachine, Cluster_stateM, is_onetime):
    # Fuzzing with "Capture"
    is_crashed = False
    if Cluster_stateM["Wait Create"]["IsThere"] and Cluster_stateM["Wait Create"]["Capture"]:
        for iter in range(1, ITER):
            opt = randint(0, (len(Cluster_stateM["Wait Create"]["Capture"])-1))
            target_trans = Cluster_stateM["Wait Create"]["Capture"][opt]
            for trans in target_trans:
                pkt = GetMPacket(trans)
                t_state = "[Captured][{}]Wait Create".format(opt)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, trans, t_state)

                if is_onetime and is_crashed:
                    return sock, is_crashed
                
            if iter % 100 == 0:
                if Check_TargetTrace(sock):
                    break
        statemachine.CURRENT_STATE = "Wait Create State"

    elif Cluster_stateM["Wait Create"]["IsThere"]:  # Fuzzing with spec
        for iter in range(1, ITER):
            pkt, cmd_code = statemachine.closed_state.Get_M_Packet(L2CAP_WAIT_CREATE_STATE)
            sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
            statemachine.CURRENT_STATE = "Wait Create State"

            if is_onetime and is_crashed:
                return sock, is_crashed
            
            if iter % 100 == 0:
                if Check_TargetTrace(sock):
                    break

        for iter in range(1, ITER):
            pkt, cmd_code = statemachine.wait_create_state.Get_M_Packet(L2CAP_CLOSED_STATE)
            sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
            statemachine.CURRENT_STATE = "Closed State"

            if is_onetime and is_crashed:
                return sock, is_crashed
            
            if iter % 100 == 0:
                if Check_TargetTrace(sock):
                    break

        if statemachine.wait_create_rsp_state.IsThere:
            for iter in range(1, ITER):
                pkt, cmd_code = statemachine.wait_create_rsp_state.Get_M_Packet(L2CAP_CLOSED_STATE)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
                statemachine.CURRENT_STATE = "Wait Create Rsp State"

                if is_onetime and is_crashed:
                    return sock, is_crashed
                
                if iter % 100 == 0:
                    if Check_TargetTrace(sock):
                        break
    else: pass
    statemachine.CURRENT_STATE = "Closed State"
    return sock, is_crashed


def connection_state_fuzzing(bt_addr, sock, statemachine, Cluster_stateM, is_onetime):
    # Target : Wait Connect, Wait Connect Rsp
    is_crashed = False
    if Cluster_stateM["Wait Connect"]["IsThere"] and Cluster_stateM["Wait Connect"]["Capture"]:
        for iter in range(1, ITER):
            opt = randint(0, (len(Cluster_stateM["Wait Connect"]["Capture"])-1))
            target_trans = Cluster_stateM["Wait Connect"]["Capture"][opt]
            for trans in target_trans:
                pkt = GetMPacket(trans)
                t_state = "[Captured][{}]Wait Connect".format(opt)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, trans, t_state)

                if is_onetime and is_crashed:
                    return sock, is_crashed
        
    elif Cluster_stateM["Wait Connect"]["IsThere"]: # Fuzzing with "Capture"
        # Fuzzing with spec
        for iter in range(1, ITER):
            pkt, cmd_code = statemachine.closed_state.Get_M_Packet(L2CAP_WAIT_CONNECT_STATE)
            sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
            statemachine.CURRENT_STATE = "Wait Connect State"
            if is_onetime and is_crashed:
                return sock, is_crashed
            pkt, cmd_code = statemachine.wait_connect_state.Get_M_Packet(L2CAP_CLOSED_STATE)
            sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
            statemachine.CURRENT_STATE = "Closed State"

            if is_onetime and is_crashed:
                return sock, is_crashed

        if statemachine.wait_connect_rsp_state.IsThere:
            for iter in range(1, ITER):
                pkt, cmd_code = statemachine.closed_state.Get_M_Packet(L2CAP_WAIT_CONNECT_RSP_STATE)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
                statemachine.CURRENT_STATE = "Wait Connect Rsp State"
                if is_onetime and is_crashed:
                    return sock, is_crashed
                
                statemachine.CURRENT_STATE = "Closed State"
                if iter % 100 == 0:
                    if Check_TargetTrace(sock):
                        break
    else: pass
    return sock, is_crashed


def enter_config(bt_addr, sock, port, statemachine):
    while(1):
        # Wait Config
        cmd_code = L2CAP_CMD_CONN_REQ
        pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConnReq(psm=port, scid=OUR_LOCAL_SCID) 
        sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
        statemachine.CURRENT_STATE = "Wait Connect State"

        global conn_rsp_flag
        global dcid_value
        print(f"conn_rsp_flag : {conn_rsp_flag}")
        if(conn_rsp_flag == 0):
            # Only one time
            conn_rsp = sock.recv() # save pkt info for configuration request
            try:
                dcid_value = conn_rsp.dcid
                result_value = conn_rsp.result
            except:
                dcid_value = OUR_LOCAL_SCID
                result_value = 1

            conn_rsp_flag = 1
            # Can't connection to selected PSM.
            if(result_value != 0):
                print("[!] Device is not paired with host('{}'). \n[!] Can't test service port that you've selected. Now set port as default PSM, '1'.".format(L2CAP_Connect_Result.get(result_value, 'reserved for future use')))
                port = 1
                continue
        break
    return dcid_value, sock


def SpecConfigfuzzing(bt_addr, sock, statemachine, dcid_value, is_onetime):
    is_crashed = False
    opt = randint(0, 1)
    if opt:
        if statemachine.wait_send_config_state.IsThere:
            for iter in range(1, ITER): # ConfigReq
                pkt, cmd_code = statemachine.wait_config_state.Get_M_Packet(L2CAP_WAIT_SEND_CONFIG_STATE, dcid_value)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
                if is_onetime and is_crashed:
                    return sock, is_crashed
                if iter % 100 == 0:
                    if Check_TargetTrace(sock):
                        break

        # from Wait Config State to Wait Send Config State
        pkt, cmd_code = statemachine.wait_config_state.Get_Tran_Packet(L2CAP_WAIT_SEND_CONFIG_STATE, dcid_value)
        sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
        statemachine.CURRENT_STATE = "Wait Send Config State"

        # 3) Target State : Wait Config Rsp State
        if statemachine.wait_config_rsp_state.IsThere:
            for iter in range(1, ITER):
                pkt, cmd_code = statemachine.wait_send_config_state.Get_M_Packet(L2CAP_WAIT_CONFIG_RSP_STATE, dcid_value)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
                if is_onetime and is_crashed:
                    return sock, is_crashed
                if iter % 100 == 0:
                    if Check_TargetTrace(sock):
                        break
        #From Wait Send Config State to Wait Config Rsp State
        pkt, cmd_code = statemachine.wait_send_config_state.Get_Tran_Packet(L2CAP_WAIT_CONFIG_RSP_STATE, dcid_value)
        sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
        statemachine.CURRENT_STATE = "Wait Config Rsp State"

        if statemachine.wait_ind_final_rsp_state.IsThere:
            for iter in range(1, ITER):
                pkt, cmd_code = statemachine.wait_config_rsp_state.Get_M_Packet(L2CAP_WAIT_IND_FINAL_RSP_STATE, dcid_value)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
                if is_onetime and is_crashed:
                    return sock, is_crashed
                if iter % 100 == 0:
                    if Check_TargetTrace(sock):
                        break
        # From Wait Config Rsp state to Wait Ind Final Rsp
        pkt, cmd_code = statemachine.wait_config_rsp_state.Get_Tran_Packet(L2CAP_WAIT_IND_FINAL_RSP_STATE, dcid_value)
        sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
        statemachine.CURRENT_STATE = "Wait Ind Final Rsp State"

        if statemachine.wait_final_rsp_state.IsThere:
            for iter in range(1, ITER):
                pkt, cmd_code = statemachine.wait_ind_final_rsp_state.Get_M_Packet(L2CAP_WAIT_FINAL_RSP_STATE, dcid_value)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
                if is_onetime and is_crashed:
                    return sock, is_crashed
                
                if iter % 100 == 0:
                    if Check_TargetTrace(sock):
                        break

        # From Wait Ind Final Rsp to Wait Final Rsp	
        pkt, cmd_code = statemachine.wait_ind_final_rsp_state.Get_Tran_Packet(L2CAP_WAIT_FINAL_RSP_STATE, dcid_value)
        sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
        statemachine.CURRENT_STATE = "Wait Final Rsp State"
		# 4-1) Target State : Wait Final Rsp
        if statemachine.open_state.IsThere:
            for iter in range(1, ITER):
                pkt, cmd_code = statemachine.wait_final_rsp_state.Get_M_Packet(L2CAP_OPEN_STATE, dcid_value)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
                if is_onetime and is_crashed:
                    return sock, is_crashed
                if iter % 100 == 0:
                    if Check_TargetTrace(sock):
                        break

		# From Wait Final Rsp to open 
        pkt, cmd_code = statemachine.wait_final_rsp_state.Get_Tran_Packet(L2CAP_OPEN_STATE, dcid_value)
        sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
        statemachine.CURRENT_STATE = "Open State"
    else:
        if statemachine.wait_config_req_rsp_state.IsThere:
            for iter in range(1, ITER):
                pkt, cmd_code = statemachine.wait_config_state.Get_M_Packet(L2CAP_WAIT_CONFIG_REQ_RSP_STATE, dcid_value)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
                if is_onetime and is_crashed:
                    return sock, is_crashed
                if iter % 100 == 0:
                    if Check_TargetTrace(sock):
                        break

        pkt, cmd_code = statemachine.wait_config_state.Get_Tran_Packet(L2CAP_WAIT_CONFIG_REQ_RSP_STATE, dcid_value)
        sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
        statemachine.CURRENT_STATE = "Wait Config Req Rsp State"

        if statemachine.wait_config_req_state.IsThere:
            for iter in range(1, ITER): 
                pkt, cmd_code = statemachine.wait_config_req_rsp_state.Get_M_Packet(L2CAP_WAIT_CONFIG_REQ_STATE, dcid_value)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
                if is_onetime and is_crashed:
                    return sock, is_crashed
                if iter % 100 == 0:
                    if Check_TargetTrace(sock):
                        break
        pkt, cmd_code = statemachine.wait_config_req_rsp_state.Get_Tran_Packet(L2CAP_WAIT_CONFIG_REQ_STATE, dcid_value)
        sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
        statemachine.CURRENT_STATE = "Wait Config Req State"

        if statemachine.wait_ind_final_rsp_state.IsThere:
            for iter in range(1, ITER): 
                pkt, cmd_code = statemachine.wait_config_req_state.Get_M_Packet(L2CAP_WAIT_IND_FINAL_RSP_STATE, dcid_value)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
                if is_onetime and is_crashed:
                    return sock, is_crashed
                if iter % 100 == 0:
                    if Check_TargetTrace(sock):
                        break
        pkt, cmd_code = statemachine.wait_config_req_state.Get_Tran_Packet(L2CAP_WAIT_IND_FINAL_RSP_STATE, dcid_value)
        sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
        statemachine.CURRENT_STATE = "Wait Ind Final Rsp State"

        if statemachine.wait_control_ind_state.IsThere:
            for iter in range(1, ITER):
                pkt, cmd_code = statemachine.wait_ind_final_rsp_state.Get_M_Packet(L2CAP_WAIT_CONTROL_IND_STATE, dcid_value)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
                if is_onetime and is_crashed:
                    return sock, is_crashed
                if iter % 100 == 0:
                    if Check_TargetTrace(sock):
                        break
        pkt, cmd_code = statemachine.wait_ind_final_rsp_state.Get_Tran_Packet(L2CAP_WAIT_CONTROL_IND_STATE, dcid_value)
        sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
        statemachine.CURRENT_STATE = "Wait Control Ind State"

        if statemachine.open_state.IsThere:
            for iter in range(1, ITER):
                pkt, cmd_code = statemachine.wait_control_ind_state.Get_M_Packet(L2CAP_OPEN_STATE, dcid_value)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)                
                if is_onetime and is_crashed:
                    return sock, is_crashed
                if iter % 100 == 0:
                    if Check_TargetTrace(sock):
                        break
        pkt, cmd_code = statemachine.wait_control_ind_state.Get_Tran_Packet(L2CAP_OPEN_STATE, dcid_value)
        sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
        statemachine.CURRENT_STATE = "Open State"
    return sock, is_crashed

def config_state_fuzzing(bt_addr, sock, statemachine, Cluster_stateM, dcid_value, is_onetime):
    is_crashed = False
    statemachine.CURRENT_STATE = "Wait Config State"

    if statemachine.wait_config_state.IsThere:
        for iter in range(1, ITER):
            pkt, cmd_code = statemachine.wait_config_state.Get_M_Packet(L2CAP_WAIT_CONFIG_STATE, dcid_value)
            sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
            if is_onetime and is_crashed:
                return sock, is_crashed
            
            if iter % 100 == 0:
                if Check_TargetTrace(sock):
                    break

    if Cluster_stateM["Wait Send Config"]["IsThere"] and Cluster_stateM["Wait Send Config"]["Capture"]:
        for iter in range(1, ITER):
            opt = randint(0, (len(Cluster_stateM["Wait Send Config"]["Capture"])-1))
            target_trans = Cluster_stateM["Wait Send Config"]["Capture"][opt]
            for trans in target_trans:
                pkt = GetMPacket(trans)
                t_state = "[Captured][{}]Wait Send Config".format(opt)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, trans, t_state)

                if is_onetime and is_crashed:
                    return sock, is_crashed
                
            if iter % 100 == 0:
                if Check_TargetTrace(sock):
                    break

    elif Cluster_stateM["Wait Config Req Rsp"]["IsThere"] and Cluster_stateM["Wait Config Req Rsp"]["Capture"]:   # pkt capture fuzzing
        for iter in range(1, ITER):
            opt = randint(0, len(Cluster_stateM["Wait Config Req Rsp"]["Capture"])-1)
            target_trans = Cluster_stateM["Wait Config Req Rsp"]["Capture"][opt]
            for trans in target_trans:
                pkt = GetMPacket(trans)
                t_state = "[Captured][{}]Wait Config Req Rsp".format(opt)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, trans, t_state)
                if is_onetime and is_crashed:
                    return sock, is_crashed
                if iter % 100 == 0:
                    if Check_TargetTrace(sock):
                        break                
    else:
        sock, is_crashed = SpecConfigfuzzing(bt_addr, sock, statemachine, dcid_value, is_onetime)
    return sock, is_crashed


def Spec_shift_state_fuzzing(bt_addr, sock, statemachine, dcid_value, is_onetime):
    is_crashed = False

	# 1) Target State : Wait Move
    if statemachine.wait_move_state.IsThere:
        for iter in range(1, ITER):
            # packet for moving from open state to wait move state with invalid movechanReq (with invalid dest_controller_id, 0x01(bt)-0x02(wifi) : valid id)
            pkt, cmd_code = statemachine.open_state.Get_M_Packet(L2CAP_WAIT_MOVE_STATE, dcid_value)
            sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)            
            if is_onetime and is_crashed:
                return sock, is_crashed
            if iter % 100 == 0:
                if Check_TargetTrace(sock):
                    break

    # from Open to Wait move 
    pkt, cmd_code = statemachine.open_state.Get_Tran_Packet(L2CAP_WAIT_MOVE_STATE, dcid_value)
    sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
    statemachine.CURRENT_STATE = "Wait Move State"

	# 2) Target State : Wait Move Confirm State
    if statemachine.wait_move_confirm_state.IsThere:
        for iter in range(1, ITER):
            # packet for moving from open state to wait move confirm state with invalid move chan confirm req (with invalid icid)
            pkt, cmd_code = statemachine.wait_move_state.Get_M_Packet(L2CAP_WAIT_MOVE_CONFIRM_STATE)
            sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)            
            if is_onetime and is_crashed:
                return sock, is_crashed
            if iter % 100 == 0:
                if Check_TargetTrace(sock):
                    break
    # from Wait Move to Wait Move Confirm State
    pkt, cmd_code = statemachine.wait_move_state.Get_Tran_Packet(L2CAP_WAIT_MOVE_CONFIRM_STATE)
    sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
    
    statemachine.CURRENT_STATE = "Wait Move Confirm State"

	# from Wait Move Confirm State to Open State
    pkt, cmd_code = statemachine.wait_move_confirm_state.Get_Tran_Packet(L2CAP_OPEN_STATE)
    sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
    statemachine.CURRENT_STATE = "Open State"

    if statemachine.wait_move_rsp_state.IsThere:
        for iter in range(1, ITER):
            pkt, cmd_code = statemachine.open_state.Get_M_Packet(L2CAP_WAIT_MOVE_RSP_STATE, dcid_value)
            sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
            if is_onetime and is_crashed:
                return sock, is_crashed
            if iter % 100 == 0:
                if Check_TargetTrace(sock):
                    break    

    # from Open State to Wait Move Rsp State
    pkt, cmd_code = statemachine.open_state.Get_Tran_Packet(L2CAP_WAIT_MOVE_RSP_STATE, dcid_value)
    sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
    statemachine.CURRENT_STATE = "Wait Move Rsp State"
    if statemachine.wait_confirm_rsp_state.IsThere:
        for iter in range(1, ITER):
            pkt, cmd_code = statemachine.wait_move_rsp_state.Get_M_Packet(L2CAP_WAIT_CONFIRM_RSP_STATE)
            sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
            if is_onetime and is_crashed:
                return sock, is_crashed
            if iter % 100 == 0:
                if Check_TargetTrace(sock):
                    break

        # from Wait move Rsp State to Wait Confirm Rsp State
        pkt, cmd_code = statemachine.wait_move_rsp_state.Get_Tran_Packet(L2CAP_WAIT_CONFIRM_RSP_STATE)
        sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
        statemachine.CURRENT_STATE = "Wait Confirm Rsp State"
        for iter in range(1, ITER):
            pkt, cmd_code = statemachine.wait_confirm_rsp_state.Get_M_Packet(L2CAP_OPEN_STATE)
            sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
            if is_onetime and is_crashed:
                return sock, is_crashed
            if iter % 100 == 0:
                if Check_TargetTrace(sock):
                    break            
    else:
        # from Wait move Rsp State to Wait Confirm Rsp State
        pkt, cmd_code = statemachine.wait_move_rsp_state.Get_Tran_Packet(L2CAP_WAIT_CONFIRM_RSP_STATE)
        sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
        statemachine.CURRENT_STATE = "Wait Confirm Rsp State"
    # from Wait Confirm Rsp State to open state
    pkt, cmd_code = statemachine.wait_confirm_rsp_state.Get_Tran_Packet(L2CAP_OPEN_STATE)
    sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
    statemachine.CURRENT_STATE = "Open State"
    return sock, is_crashed


def shift_state_fuzzing(bt_addr, sock, statemachine, Cluster_stateM, dcid_value, is_onetime):
    is_crashed = False
    if Cluster_stateM["Wait Move"]["IsThere"] and Cluster_stateM["Wait Move"]["Capture"]:   #pkt capture fuzzing
        opt = randint(0, len(Cluster_stateM["Wait Move"]["Capture"])-1)
        target_trans = Cluster_stateM["Wait Move"]["Capture"][opt]
        for trans in target_trans:
            pkt = GetMPacket(trans)
            t_state = "[Captured][{}]Wait Move".format(opt)
            sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, trans, t_state)
            if is_onetime and is_crashed:
                return sock, is_crashed
    elif Cluster_stateM["Wait Move Rsp"]["IsThere"] and Cluster_stateM["Wait Move Rsp"]["Capture"]:     # pkt capture fuzzing
        opt = randint(0, len(Cluster_stateM["Wait Move Rsp"]["Capture"])-1)
        target_trans = Cluster_stateM["Wait Move Rsp"]["Capture"][opt]
        for trans in target_trans:
            pkt = GetMPacket(trans)
            t_state = "[Captured][{}]Wait Move Rsp".format(opt)
            sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, trans, t_state)
            if is_onetime and is_crashed:
                return sock, is_crashed
    else:
        sock, is_crashed = Spec_shift_state_fuzzing(bt_addr, sock, statemachine, dcid_value, is_onetime)
    return sock, is_crashed


def disconnection_state_fuzzing(bt_addr, sock, statemachine, Cluster_stateM, dcid_value, is_onetime):
    is_crashed = False
    if Cluster_stateM["Wait Disconnect"]["IsThere"] and Cluster_stateM["Wait Disconnect"]["Capture"]:
        for iter in range(1, ITER):
            opt = randint(0, (len(Cluster_stateM["Wait Disconnect"]["Capture"])-1))
            target_trans = Cluster_stateM["Wait Disconnect"]["Capture"][opt]
            for trans in target_trans:
                pkt = GetMPacket(trans)
                t_state = "[Captured][{}]Wait Disconnect".format(opt)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, trans, t_state)
                if is_onetime and is_crashed:
                    return sock, is_crashed
            
            if iter % 100 == 0:
                if Check_TargetTrace(sock):
                    break
        statemachine.CURRENT_STATE = "Wait Disconnect State"
    elif Cluster_stateM["Wait Disconnect"]["IsThere"]:
        if statemachine.wait_disconnect_state.IsThere:
            for iter in range(1, ITER):
                pkt, cmd_code = statemachine.open_state.Get_M_Packet(L2CAP_WAIT_DISCONNECT_STATE, dcid_value)
                sock, is_crashed = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
                if is_onetime and is_crashed:
                    return sock, is_crashed
                if iter % 100 == 0:
                    if Check_TargetTrace(sock):
                        break
            statemachine.CURRENT_STATE = "Wait Disconnect State"
    else: pass
        
    pkt, cmd_code = statemachine.open_state.Get_Tran_Packet(L2CAP_CLOSED_STATE, dcid_value)
    sock, _ = fuz_send_pkt(bt_addr, sock, pkt, cmd_code, statemachine.CURRENT_STATE)
    statemachine.CURRENT_STATE = "Closed State"
    return sock, is_crashed


def logsave(loggerDict):
    loggerDict["end_time"] = str(datetime.now())
    loggerDict["count"] = {"all" : pkt_cnt, "crash" : crash_cnt, "passed" : pkt_cnt-crash_cnt}
    logger.inputQueue("**ITEREND**")
    logger.logUpdate()
    logger.init_info(loggerDict)


def fuzzing(bt_addr, profile, port, statemachine, Cluster_stateM, test_info, dcid_value, is_onetime):
    global crash_cnt
    test_info["starting_time"] = str(now)
    logger.init_info(test_info)
    if(profile == "None" or port == "None"):
        print('Cannot Fuzzing')
        return
    print("Start Fuzzing... Please hit Ctrl + C to finish...")

    sock = BluetoothL2CAPSocket(bt_addr)
    logger.start = time.time()

    try:
        while True:
            print("[+] Tested %d packets" % (pkt_cnt))
            statemachine.CURRENT_STATE = "Closed State"
            loggerDict = OrderedDict()

            sock, is_crashed = creation_state_fuzzing(bt_addr, sock, statemachine, Cluster_stateM, is_onetime)
            if is_crashed: break

            sock, is_crashed = connection_state_fuzzing(bt_addr, sock, statemachine, Cluster_stateM, is_onetime)
            if is_crashed: break

            sock, is_crashed = config_state_fuzzing(bt_addr, sock, statemachine, Cluster_stateM, dcid_value, is_onetime)
            if is_crashed: break

            sock, is_crashed = shift_state_fuzzing(bt_addr, sock, statemachine, Cluster_stateM, dcid_value, is_onetime)
            if is_crashed: break

            sock, is_crashed = disconnection_state_fuzzing(bt_addr, sock, statemachine, Cluster_stateM, dcid_value, is_onetime)
            if is_crashed: break

            sock.close()
            logger.inputQueue("**ITEREND**")
            print("********************************************************************")

            sock = BluetoothL2CAPSocket(bt_addr)
            logger.end = time.time()

            if logger.end - logger.start > 60:
                logger.start = time.time()
                t1 = threading.Thread(target=logger.logUpdate())
                t1.start()
            
            if pkt_cnt > 2000000:
                print("[+] Save logfile")
                print("iteration END@@@@@@@@@")
                logsave(loggerDict)
                break
        if is_crashed:
            print("[+] Save logfile")
            print("iteration END@@@@@@@@@")
            logger.inputQueue("**ITEREND**")
            logsave(loggerDict)

    except Exception as e:
        print("[!] Error Message :", e, traceback.format_exc())
        print("[+] Save logfile")
        loggerDict["count"] = {"all" : pkt_cnt, "crash" : crash_cnt, "passed" : pkt_cnt-crash_cnt}
        logsave(loggerDict)

    except KeyboardInterrupt as k:
        print("[!] Fuzzing Stopped :", k, traceback.format_exc())
        print("[+] Save logfile")
        loggerDict["end_time"] = str(datetime.now())
        loggerDict["count"] = {"all" : pkt_cnt, "crash" : crash_cnt, "passed" : pkt_cnt-crash_cnt}
        print("[*] Assign queue update for key interrupt to thread")
        logsave(loggerDict)
    
    print(f"Total pkt cnt: {pkt_cnt}, crashcnt : {crash_cnt}")