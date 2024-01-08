from lib import *
from time import sleep

# for time out recv
from functools import wraps
import errno
import os
import signal

class TimeoutError(Exception):
    pass

def timeout(seconds=10, error_message=os.strerror(errno.ETIME)):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.setitimer(signal.ITIMER_REAL,seconds) #used timer instead of alarm
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result
        return wraps(func)(wrapper)
    return decorator

@timeout(3)
def inter_recv(sock):
    conn_rsp, sock, flag = recv_pkt(sock)
    return conn_rsp, sock, flag


def w_create_check(bt_addr, sock, statemachine):
    print("  * Start W_Create Check")
    while(1):
        # WAIT CREATE CHECK
        pkt = L2CAP_CmdHdr(code=0x0C)/L2CAP_Create_Channel_Request(psm=0x01)

        sock, flag = send_pkt(bt_addr, sock, pkt)
        if not flag :
            continue
        conn_rsp, sock, flag = recv_pkt(sock)
        if not flag:
            statemachine.wait_create_state.IsThere = False
            break
        conn_rsp_code = conn_rsp.code
        if conn_rsp_code == int(L2CAP_CMD_DISCONN_REQ) or \
            conn_rsp_code == int(L2CAP_CMD_DISCONN_RSP):
            continue
        if conn_rsp_code != int(L2CAP_CMD_CREATE_CHANNEL_REQ) or int(L2CAP_CMD_CREATE_CHANNEL_RSP):
            statemachine.wait_create_state.IsThere = False
            break
        statemachine.CURRENT_STATE = "Wait Create State"
        break

    while(1):
        # WAIT CREATE RSP CHECK
        pkt = L2CAP_CmdHdr(code=0x0D)/L2CAP_Create_Channel_Response(dcid=OUR_LOCAL_SCID, scid=OUR_LOCAL_SCID)
        sock, flag = send_pkt(bt_addr, sock, pkt)
        
        if not flag : 
            continue
        conn_rsp, sock, flag = recv_pkt(sock)
        if not flag:
            break

        conn_rsp_code = conn_rsp.code
        if conn_rsp_code == int(L2CAP_CMD_DISCONN_REQ) or \
            conn_rsp_code == int(L2CAP_CMD_DISCONN_RSP):
            continue

        if conn_rsp_code != int(L2CAP_CMD_CREATE_CHANNEL_REQ)  and \
            conn_rsp_code != int(L2CAP_CMD_CREATE_CHANNEL_RSP) :
            break
        if conn_rsp_code == int(L2CAP_CMD_REJECT):
            statemachine.wait_create_state.IsThere = False
            break
        statemachine.wait_create_rsp_state.IsThere = True
        statemachine.CURRENT_STATE = "Wait Create Rsp State"
        break
    return sock

def w_conn_rsp_check(bt_addr, sock, statemachine):
    # If RSP is sent to target, Target sends req. existence
    print("  * Start W_Connect_Rsp Check")
    while(1):
        pkt = L2CAP_CmdHdr(code=L2CAP_CMD_CONN_RSP)/L2CAP_ConnResp(dcid=OUR_LOCAL_SCID, scid=OUR_LOCAL_SCID)
        sock, flag = send_pkt(bt_addr, sock, pkt)
        if not flag :
            continue
        count = 0
        while count < 3:
            try:
                conn_rsp, sock, flag = inter_recv(sock)
                break
            except Exception as e:
                flag = False
                conn_rsp = ""
                count += 1

        if not flag:
            break

        conn_rsp_code = conn_rsp.code
        if conn_rsp_code == int(L2CAP_CMD_DISCONN_REQ) or \
            conn_rsp_code == int(L2CAP_CMD_DISCONN_RSP):
            continue
        if conn_rsp_code != int(L2CAP_CMD_CONN_REQ) and \
            conn_rsp_code != int(L2CAP_CMD_CONN_RSP):
            break
        statemachine.wait_connect_rsp_state.IsThere = True
        statemachine.CURRENT_STATE = "Wait Connect Rsp State"
        break
    
    pkt = L2CAP_CmdHdr(code=L2CAP_CMD_CONN_RSP)/L2CAP_ConnResp(dcid=OUR_LOCAL_SCID, scid=OUR_LOCAL_SCID, result = 0x0004)
    sock, flag = send_pkt(bt_addr, sock, pkt)
    return sock

# [W_Conn_S, W_Conf_S] Closed -> Wait Connect State, Wait Config State
def w_conn_w_conf_check(bt_addr, sock, statemachine):
    print("  * Start W_Connect Check")

    while(1):   #WAIT CONN CHECK
        pkt = L2CAP_CmdHdr(code=L2CAP_CMD_CONN_REQ)/new_L2CAP_ConnReq(psm=random_psm())/garbage_value(garbage=randrange(0x0000, 0x10000))
        sock, flag = send_pkt(bt_addr, sock, pkt)
        if not flag :
            continue

        conn_rsp, sock, flag = recv_pkt(sock)
        if not flag:
            statemachine.wait_connect_state.IsThere = False
            break

        conn_rsp_code = conn_rsp.code

        if conn_rsp_code == int(L2CAP_CMD_DISCONN_REQ) or \
            conn_rsp_code == int(L2CAP_CMD_DISCONN_RSP):
            continue

        if conn_rsp_code != int(L2CAP_CMD_CONN_REQ) and \
            conn_rsp_code != int(L2CAP_CMD_CONN_RSP):
            statemachine.wait_connect_state.IsThere = False
            break
        statemachine.CURRENT_STATE = "Wait Connect State"
        break

    pkt = L2CAP_CmdHdr(code=L2CAP_CMD_CONN_RSP)/new_L2CAP_ConnResp(dcid=randrange(0x0040, 0x10000), scid=randrange(0x0040, 0x10000))/garbage_value(garbage=randrange(0x0000, 0x10000))
    sock, flag = send_pkt(bt_addr, sock, pkt)
    return sock


def waitconfig_check(bt_addr, sock, port, statemachine):
    while(1):
        pkt = L2CAP_CmdHdr(code=L2CAP_CMD_CONN_REQ)/L2CAP_ConnReq(psm=port, scid=OUR_LOCAL_SCID)
        sock, flag = send_pkt(bt_addr, sock, pkt)

        if not flag :
            continue
        

        conn_rsp_flag = 0
        dcid_value = 0
        
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
    statemachine.CURRENT_STATE = "Wait Config State"
    statemachine.wait_config_state.IsThere = True
    return sock, dcid_value

def conf_check(bt_addr, sock, port, statemachine):
    flag = True
    print("  * Start W_Conf Check")
    sock, dcid_value = waitconfig_check(bt_addr, sock, port, statemachine)

    print("  * Start W_Send_Conf Check")
    pkt = L2CAP_CmdHdr(code=L2CAP_CMD_CONFIG_REQ)/L2CAP_ConfReq(dcid=dcid_value)
    while(1):
        sock, flag = send_pkt(bt_addr, sock, pkt)
        if not flag:
            continue

        conn_rsp = sock.recv()
        conn_rsp_code = conn_rsp.code
        if conn_rsp_code == int(L2CAP_CMD_DISCONN_REQ) or \
            conn_rsp_code == int(L2CAP_CMD_DISCONN_RSP):
            continue

        if conn_rsp_code != int(L2CAP_CMD_CONFIG_REQ) and \
            conn_rsp_code != int(L2CAP_CMD_CONFIG_RSP):
            statemachine.wait_send_config_state.IsThere = False
        else: 
            statemachine.CURRENT_STATE = "Wait Send Config State"
        break
    print("  * Start W_Conf_Rsp, W_Ind_Final_Rsp Check")
    while(1):
        pkt = L2CAP_CmdHdr(code=L2CAP_CMD_CONFIG_RSP)/L2CAP_ConfResp(scid=dcid_value)
        sock, flag = send_pkt(bt_addr, sock, pkt)
        if not flag:
            continue

        conn_rsp, sock, flag = recv_pkt(sock)
        if repr(conn_rsp) == '':
            continue

        if not flag : # recv fail.
            statemachine.wait_config_rsp_state.IsThere = False
            statemachine.wait_ind_final_rsp_state.IsThere = False
            break

        conn_rsp_code = conn_rsp.code

        if conn_rsp_code == int(L2CAP_CMD_DISCONN_REQ) or \
            conn_rsp_code == int(L2CAP_CMD_DISCONN_RSP):
            continue

        if conn_rsp_code != int(L2CAP_CMD_CONFIG_REQ) and \
            conn_rsp_code != int(L2CAP_CMD_CONFIG_RSP):
            statemachine.wait_config_rsp_state.IsThere = False
            statemachine.wait_ind_final_rsp_state.IsThere = False
        else:
            statemachine.CURRENT_STATE = "Wait Ind Final Rsp State"
        break

    if statemachine.wait_ind_final_rsp_state.IsThere:
        sock = conf_path1_check(bt_addr, sock, statemachine, dcid_value)
        #-> wait_config_state -> Wait Send Config State -> Wait Config Rsp, Wait Ind Final Rsp State
        while(1):
            pkt = L2CAP_CmdHdr(code=0x02)/L2CAP_ConnReq(psm=port, scid=dcid_value)
            sock, flag = send_pkt(bt_addr, sock, pkt)
            if flag:
                break
        statemachine.CURRENT_STATE = "Wait Config State"
        i = 0
        while(1):
            pkt = L2CAP_CmdHdr(code=L2CAP_CMD_CONFIG_RSP)/L2CAP_ConfResp(scid=dcid_value)
            sock, flag = send_pkt(bt_addr, sock, pkt)
            if not flag:
                continue

            conn_rsp, sock, flag = recv_pkt(sock)
            i += 1
            if i > 5:
                statemachine.wait_config_req_rsp_state.IsThere = False
                break
            if repr(conn_rsp) == '':
                continue

            if not flag : #recv fail.
                statemachine.wait_config_req_rsp_state.IsThere = False
                break

            conn_rsp_code = conn_rsp.code

            if conn_rsp_code == int(L2CAP_CMD_DISCONN_REQ) or \
                conn_rsp_code == int(L2CAP_CMD_DISCONN_RSP):
                continue
            
            if conn_rsp_code != int(L2CAP_CMD_CONFIG_REQ) and \
                conn_rsp_code != int(L2CAP_CMD_CONFIG_RSP):
                statemachine.wait_config_req_rsp_state.IsThere = False
            else:
                statemachine.wait_config_req_rsp_state.IsThere = True
            break

        statemachine.CURRENT_STATE = "Wait Config Req Rsp State"
        while(1):
            pkt = L2CAP_CmdHdr(code=L2CAP_CMD_CONFIG_RSP)/L2CAP_ConfResp(scid=dcid_value)
            sock, flag = send_pkt(bt_addr, sock, pkt)
            if not flag: continue
            if statemachine.wait_config_req_rsp_state.IsThere:
                statemachine.wait_config_req_state.IsThere = True
            else:
                statemachine.wait_config_req_state.IsThere = False
            statemachine.CURRENT_STATE = "Wait Config Req State"
            break

        pkt = L2CAP_CmdHdr(code=L2CAP_CMD_CONFIG_REQ)/L2CAP_ConfReq(dcid=dcid_value)
        while(1):
            sock, flag = send_pkt(bt_addr, sock, pkt)
            if not flag: continue
            break
        statemachine.CURRENT_STATE = "Wait Ind Final Rsp State"
        # Wait Ind Final Rsp State -> Wait Control Ind State -> Open
        sock = conf_path2_check(bt_addr, sock, statemachine, dcid_value)
    else:
        statemachine.wait_final_rsp_state.IsThere = False
        statemachine.wait_control_ind_state.IsThere = False
        pkt, _ = statemachine.wait_config_rsp_state.Get_Tran_Packet(L2CAP_OPEN_STATE, dcid_value)
        sock, flag = send_pkt(bt_addr, sock, pkt)
        statemachine.CURRENT_STATE = "Open State"
    return sock, dcid_value


def conf_path1_check(bt_addr, sock, statemachine, dcid_value):
    # Wait Final RSP
    print("  * Start W_Final_Rsp Check")
    while(1):
        pkt, _ = statemachine.wait_ind_final_rsp_state.Get_Tran_Packet(L2CAP_WAIT_FINAL_RSP_STATE, dcid_value)
        sock, flag = send_pkt(bt_addr, sock, pkt)
        if not flag:
            continue
        conn_rsp, sock, flag = recv_pkt(sock)
        if not flag: # recv fail.
            statemachine.wait_final_rsp_state.IsThere = False
            continue

        conn_rsp_code = conn_rsp.code

        if conn_rsp_code == int(L2CAP_CMD_DISCONN_REQ) or \
            conn_rsp_code == int(L2CAP_CMD_DISCONN_RSP):
            continue
        if conn_rsp_code != int(L2CAP_CMD_CONFIG_REQ) and \
            conn_rsp_code != int(L2CAP_CMD_CONFIG_RSP):
            statemachine.wait_final_rsp_state.IsThere = False
        else:
            statemachine.CURRENT_STATE = "Wait Final Rsp State"
        break
    return sock


def conf_path2_check(bt_addr, sock, statemachine, dcid_value):
    pkt, _ = statemachine.wait_ind_final_rsp_state.Get_Tran_Packet(L2CAP_WAIT_CONTROL_IND_STATE, dcid_value)
    print("  * Start W_Ctrl_Ind Check")
    while(1):
        sock, flag = send_pkt(bt_addr, sock, pkt)
        if not flag:
            continue

        conn_rsp, sock, flag = recv_pkt(sock)
        if not flag: # recv fail.
            statemachine.wait_control_ind_state.IsThere = False
            break

        conn_rsp_code = conn_rsp.code

        if conn_rsp_code == int(L2CAP_CMD_DISCONN_REQ) or \
            conn_rsp_code == int(L2CAP_CMD_DISCONN_RSP):
            continue

        if conn_rsp_code != int(L2CAP_CMD_CONFIG_REQ) and \
            conn_rsp_code != int(L2CAP_CMD_CONFIG_RSP):
            statemachine.wait_control_ind_state.IsThere = False
        else:
            statemachine.CURRENT_STATE = "Wait Control Ind State"
        break
    # Wait control ind -> open
    pkt = L2CAP_CmdHdr(code=L2CAP_CMD_CONFIG_REQ)/L2CAP_ConfReq(dcid=dcid_value)
    sock, flag = send_pkt(bt_addr, sock, pkt)
    statemachine.CURRENT_STATE = "Open State"
    return sock


def move_check(bt_addr, sock, dcid_value, statemachine):
    print("  * Start Move Check")
    while(1):
        pkt = L2CAP_CmdHdr(code=L2CAP_CMD_MOVE_CHANNEL_REQ)/L2CAP_Move_Channel_Request(dest_controller_id=0)
        sock, flag = send_pkt(bt_addr, sock, pkt)
        if not flag: continue
        
        conn_rsp, sock, flag = recv_pkt(sock)
        if not flag: continue        #recv fail.
        conn_rsp_code = conn_rsp.code

        if conn_rsp_code == int(L2CAP_CMD_MOVE_CHANNEL_REQ):
            statemachine.wait_move_rsp_state.IsThere = True
            statemachine.CURRENT_STATE = "Wait Move Rsp State"
        elif conn_rsp_code == int(L2CAP_CMD_MOVE_CHANNEL_RSP):
            statemachine.wait_move_state.IsThere = True
            statemachine.wait_move_confirm_state.IsThere = True
            statemachine.CURRENT_STATE = "Wait Move State"
            statemachine.CURRENT_STATE = "Wait Move Confirm State"
        else:
            statemachine.wait_move_state.IsThere = False
            statemachine.wait_move_confirm_state.IsThere = False
            statemachine.wait_move_rsp_state.IsThere = False
            statemachine.wait_confirm_rsp_state.IsThere = False
        break
    pkt, _ = statemachine.open_state.Get_Tran_Packet(L2CAP_CLOSED_STATE, dcid_value)
    sock, flag = send_pkt(bt_addr, sock, pkt)
    statemachine.CURRENT_STATE = "Closed State"
    return sock


def SpecState_Pruning(bt_addr, sock, port, statemachine):
    print("[+] Start STATE Traveral")
    while(1):
        try:
            sock = w_create_check(bt_addr, sock, statemachine)
            sleep(0.1)
        except ConnectionResetError:
            continue
        break
    while(1):
        try:
            sock = w_conn_rsp_check(bt_addr, sock, statemachine)
            sleep(0.1)
        except ConnectionResetError:
            continue
        break
    while(1):
        try:
            sock = w_conn_w_conf_check(bt_addr, sock, statemachine)
        except ConnectionResetError:
            continue
        break
    while(1):
        try:
            sock, dcid_value = conf_check(bt_addr, sock, port, statemachine)
        except ConnectionResetError:
            continue
        break
    while(1):
        try:
            sock = move_check(bt_addr, sock, dcid_value, statemachine)
        except ConnectionResetError:
            continue
        break
 
    return statemachine, sock, dcid_value