# from statemachine import StateMachine, State
from scapy.all import *
from scapy.layers.bluetooth import *

from lib.btpacket import *
from lib.Mutate_Oper import *

OUR_LOCAL_SCID = 0x40
IDNETFY = 0

#### States ####
# Basic States
class STATE:
    IsThere = False
    name = ""


class CLOSED_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere
    def Get_M_Packet(self, dst):
        if dst == L2CAP_CLOSED_STATE:
            #need for puzzing
            pkt = ""
            cmd_code = ""
        elif dst == L2CAP_WAIT_CONNECT_STATE:
            # ConnReq(fail) -> ConnRsp(pending)
            cmd_code = L2CAP_CMD_CONN_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConnReq(psm=random_psm())
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CONNECT_RSP_STATE:
            cmd_code = L2CAP_CMD_CONN_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConnResp(dcid=OUR_LOCAL_SCID, scid=OUR_LOCAL_SCID)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CREATE_STATE:
            # CreateChanReq(fail) -> CreateChanRsp(pending)
            cmd_code = L2CAP_CMD_CREATE_CHANNEL_REQ
            # p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_CMD_CREATE_CHANNEL_REQuest(psm=random_psm())
            p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Create_Channel_Request(psm=random_psm())
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CREATE_RSP_STATE:
            pkt = ""
            cmd_code = ""
        else:
            print(f"Dst : {dst}")
            assert False, "CLOSED_STATE Dst Match is not working"
        return pkt, cmd_code


class OPEN_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere
    def Get_Tran_Packet(self, dst, dcid_value):
        if dst == L2CAP_WAIT_MOVE_STATE:
            cmd_code = L2CAP_CMD_MOVE_CHANNEL_REQ
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Request(dest_controller_id=0)
        elif dst == L2CAP_WAIT_MOVE_RSP_STATE:
            cmd_code = L2CAP_CMD_MOVE_CHANNEL_RSP
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Response(icid=0x00, result=0)
        elif dst == L2CAP_CLOSED_STATE:
            cmd_code = L2CAP_CMD_DISCONN_REQ
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_DisconnReq(scid=OUR_LOCAL_SCID, dcid=dcid_value)
        else:
            print(f"Dst : {dst}")
            assert False, "OPEN_STATE Dst Match is not working"
        return pkt, cmd_code

    def Get_M_Packet(self, dst, dcid_value):
        if dst == L2CAP_WAIT_DISCONNECT_STATE:
            cmd_code = L2CAP_CMD_DISCONN_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_DisconnReq(scid=OUR_LOCAL_SCID, dcid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CONFIG_REQ_RSP_STATE:
            # It depends on whether there is a dcid of the packet received as recv() when entering Wait config. See l2cap_fuzzer.py/L 528
            # pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConfReq(dcid=dcid_value)
            cmd_code = L2CAP_CMD_CONFIG_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfReq(dcid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_CLOSED_STATE:
            cmd_code = ""
            pkt = ""
        elif dst == L2CAP_WAIT_MOVE_STATE:
            cmd_code = L2CAP_CMD_MOVE_CHANNEL_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Request(dest_controller_id=0)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_MOVE_CONFIRM_STATE:
            cmd_code = L2CAP_CMD_MOVE_CHANNEL_CONFIRM_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Confirmation_Request(icid=0x00)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_MOVE_RSP_STATE:
            cmd_code = L2CAP_CMD_MOVE_CHANNEL_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Response(icid=0x00)
            pkt = Mutate_Packet(cmd_code, p)
        else:
            print(f"Dst : {dst}")
            assert False, "OPEN_STATE Dst Match is not working"
        return pkt, cmd_code


class WAIT_CONFIG_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere
    def Get_Tran_Packet(self, dst, dcid_value):
        if dst == L2CAP_WAIT_SEND_CONFIG_STATE:
            cmd_code = L2CAP_CMD_CONFIG_REQ
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConfReq(dcid=dcid_value)
        elif dst == L2CAP_WAIT_CONFIG_REQ_RSP_STATE:
            cmd_code = L2CAP_CMD_CONFIG_RSP
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConfResp(scid=dcid_value)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CONFIG_STATE Dst Match is not working"
        return pkt, cmd_code

    def Get_M_Packet(self, dst, dcid_value):
        if dst == L2CAP_WAIT_SEND_CONFIG_STATE:
            # It depends on whether there is dcid of packet received as recv() when entering Wait config. see l2cap_fuzzer.py/L 528
            cmd_code = L2CAP_CMD_CONFIG_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfReq(dcid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CONFIG_STATE:
            cmd_code = L2CAP_CMD_CONFIG_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfReq(dcid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CONFIG_REQ_RSP_STATE:
            cmd_code = L2CAP_CMD_CONFIG_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfResp(scid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CONFIG_STATE Dst Match is not working"
        return pkt, cmd_code


class WAIT_CONNECT_STATE(STATE):

    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere
    def Get_M_Packet(self, dst):
        if dst == L2CAP_CLOSED_STATE:
            cmd_code = L2CAP_CMD_CONN_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConnReq(psm=random_psm())
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CONFIG_STATE:
            cmd_code = ""
            pkt = ""
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CONNECT_STATE Dst Match is not working"
        return pkt, cmd_code


class WAIT_CONNECT_RSP_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere

    def Get_M_Packet(self, dst):
        if dst == L2CAP_CLOSED_STATE:
            cmd_code = L2CAP_CMD_CONN_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConnResp(dcid=OUR_LOCAL_SCID, scid=OUR_LOCAL_SCID)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CONNECT_RSP_STATE:
            cmd_code = ""
            pkt = ""
        elif dst == L2CAP_WAIT_CONFIG_STATE:
            cmd_code = ""
            pkt = ""
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CONNECT_RSP_STATE Dst Match is not working"
        return pkt, cmd_code


class WAIT_DISCONNECT_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere

    def Get_Tran_Packet(self, dst, dcid_value):
        if dst == L2CAP_CLOSED_STATE:
            cmd_code = L2CAP_CMD_DISCONN_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_DisconnReq(scid=OUR_LOCAL_SCID, dcid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_DISCONNECT_STATE Dst Match is not working"
        return pkt, cmd_code
    
    def Get_M_Packet(self, dst):
        if dst == L2CAP_CLOSED_STATE:
            pkt = ""
            cmd_code = ""
        elif dst == L2CAP_WAIT_DISCONNECT_STATE:
            pkt = ""
            cmd_code = ""
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_DISCONNECT_STATE Dst Match is not working"            
        return pkt, cmd_code
    

# Optional States (Alternative MAC/PHY enabled operation)
class WAIT_CREATE_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere
    def Get_M_Packet(self, dst):
        if dst == L2CAP_CLOSED_STATE:
            # CreateChanRsp(Refused)
            cmd_code = L2CAP_CMD_CREATE_CHANNEL_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Create_Channel_Response(dcid=OUR_LOCAL_SCID, scid=OUR_LOCAL_SCID)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CONFIG_STATE:
            cmd_code = ""
            pkt = ""
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CREATE_STATE의 Dst match is not working"
        return pkt, cmd_code
    

class WAIT_CREATE_RSP_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere
    def Get_M_Packet(self, dst):
        if dst == L2CAP_CLOSED_STATE:
            cmd_code = L2CAP_CMD_CREATE_CHANNEL_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Create_Channel_Response(dcid=OUR_LOCAL_SCID, scid=OUR_LOCAL_SCID)
            pkt = Mutate_Packet(cmd_code, p)
 
        elif dst == L2CAP_WAIT_CREATE_RSP_STATE:
            cmd_code = ""
            pkt = ""
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CREATE_RSP_STATE의 Dst match is not working"
        return pkt, cmd_code


class WAIT_MOVE_CONFIRM_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere
    def Get_Tran_Packet(self, dst):
        if dst == L2CAP_OPEN_STATE:
            cmd_code = L2CAP_CMD_MOVE_CHANNEL_CONFIRM_REQ
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Confirmation_Request(icid=0x00, result=1)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_MOVE_CONFIRM_STATE Dst Match is not working"              
        return pkt, cmd_code
    def Get_M_Packet(self, dst):
        if dst == L2CAP_OPEN_STATE:
            cmd_code = L2CAP_CMD_MOVE_CHANNEL_CONFIRM_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Confirmation_Request(icid=0x00)
            pkt = Mutate_Packet(cmd_code, p)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_MOVE_CONFIRM_STATE Dst Match is not working"  
        return pkt, cmd_code
    

class WAIT_MOVE_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere

    def Get_Tran_Packet(self, dst):
        if dst == L2CAP_WAIT_MOVE_CONFIRM_STATE:
            cmd_code = L2CAP_CMD_MOVE_CHANNEL_REQ
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Request(dest_controller_id=0)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_MOVE_STATE Dst Match is not working"  
        return pkt, cmd_code
    
    def Get_M_Packet(self, dst):
        if dst == L2CAP_WAIT_MOVE_CONFIRM_STATE:
            cmd_code = L2CAP_CMD_MOVE_CHANNEL_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Request(dest_controller_id=0)
            pkt = Mutate_Packet(cmd_code, p)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_MOVE_STATE Dst Match is not working"  
        return pkt, cmd_code
    

class WAIT_MOVE_RSP_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere

    def Get_Tran_Packet(self, dst):
        if dst == L2CAP_WAIT_CONFIRM_RSP_STATE:
            cmd_code = L2CAP_CMD_MOVE_CHANNEL_RSP
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Response(icid=0x00, result=0)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_MOVE_RSP_STATE Dst Match is not working"
        return pkt, cmd_code
    def Get_M_Packet(self, dst):
        if dst == L2CAP_WAIT_MOVE_CONFIRM_STATE:
            cmd_code = ""
            pkt = ""
        elif dst == L2CAP_WAIT_MOVE_STATE:
            cmd_code = ""
            pkt = ""
        elif dst == L2CAP_WAIT_MOVE_RSP_STATE:
            cmd_code = ""
            pkt = ""
        elif dst == L2CAP_WAIT_CONFIRM_RSP_STATE:
            cmd_code = L2CAP_CMD_MOVE_CHANNEL_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Response(icid=0x00)
            pkt = Mutate_Packet(cmd_code, p)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_MOVE_RSP_STATE Dst Match is not working"
        return pkt, cmd_code
    

class WAIT_CONFIRM_RSP_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere
    def Get_Tran_Packet(self,dst):
        if dst == L2CAP_OPEN_STATE:
            cmd_code = L2CAP_CMD_MOVE_CHANNEL_CONFIRM_RSP
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Confirmation_Response(icid=0x00)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CONFIRM_RSP_STATE Dst Match is not working"
        return pkt, cmd_code

    def Get_M_Packet(self, dst):
        if dst == L2CAP_OPEN_STATE:
            cmd_code = L2CAP_CMD_MOVE_CHANNEL_CONFIRM_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Confirmation_Response(icid=0x00)
            pkt = Mutate_Packet(cmd_code, p)            
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CONFIRM_RSP_STATE Dst Match is not working"
        return pkt, cmd_code
    
# Configurateion States
class WAIT_SEND_CONFIG_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere

    def Get_Tran_Packet(self, dst, dcid_value):
        if dst == L2CAP_WAIT_CONFIG_RSP_STATE:
            cmd_code = L2CAP_CMD_CONFIG_RSP
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConfResp(scid=dcid_value)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_SEND_CONFIG_STATE Dst Match is not working"
        return pkt, cmd_code
    
    def Get_M_Packet(self, dst, dcid_value):
        if dst == L2CAP_WAIT_CONFIG_RSP_STATE:
            # state transition (L2CAP_ConfigReq will be sent from target device. From Wait Send Config State to Wait Config Rsp state)
            cmd_code = L2CAP_CMD_CONFIG_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfResp(scid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_SEND_CONFIG_STATE Dst Match is not working"
        return pkt, cmd_code
    
class WAIT_CONFIG_REQ_RSP_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere
    def Get_Tran_Packet(self, dst, dcid_value):
        if dst == L2CAP_WAIT_CONFIG_REQ_STATE:
            cmd_code = L2CAP_CMD_CONFIG_RSP
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConfResp(scid=dcid_value)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CONFIG_REQ_RSP_STATE Dst Match is not working"            
        return pkt, cmd_code
    
    def Get_M_Packet(self, dst, dcid_value):
        if dst == L2CAP_WAIT_CONFIG_REQ_RSP_STATE:
            cmd_code = ""
            pkt = ""
        elif dst == L2CAP_WAIT_CONFIG_REQ_STATE:
            cmd_code = L2CAP_CMD_CONFIG_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfResp(scid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CONFIG_RSP_STATE:
            cmd_code = L2CAP_CMD_CONFIG_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfReq(dcid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CONFIG_REQ_RSP_STATE Dst Match is not working"  
        return pkt, cmd_code

class WAIT_CONFIG_REQ_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere
    def Get_Tran_Packet(self, dst, dcid_value):
        if dst == L2CAP_WAIT_IND_FINAL_RSP_STATE:
            cmd_code = L2CAP_CMD_CONFIG_REQ
            pkt = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfReq(dcid=dcid_value)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CONFIG_REQ_STATE Dst Match is not working"  
        return pkt, cmd_code
    def Get_M_Packet(self, dst, dcid_value):
        if dst == L2CAP_OPEN_STATE:
            cmd_code = ""
            pkt = ""
        elif dst == L2CAP_WAIT_IND_FINAL_RSP_STATE:
            cmd_code = L2CAP_CMD_CONFIG_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfReq(dcid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CONFIG_REQ_STATE:
            cmd_code = ""
            pkt = ""
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CONFIG_REQ_STATE Dst Match is not working"  
        return pkt, cmd_code

class WAIT_CONFIG_RSP_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere

    def Get_Tran_Packet(self, dst, dcid_value):
        if dst == L2CAP_WAIT_IND_FINAL_RSP_STATE:
            cmd_code = L2CAP_CMD_CONFIG_RSP
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConfResp(scid=dcid_value)
        elif dst == L2CAP_OPEN_STATE:
            cmd_code = L2CAP_CMD_CONFIG_RSP
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConfResp(scid=dcid_value)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CONFIG_RSP_STATE Dst Match is not working"              
        return pkt, cmd_code
    def Get_M_Packet(self, dst, dcid_value):
        if dst == L2CAP_OPEN_STATE:
            cmd_code = ""
            pkt = ""
        elif dst == L2CAP_WAIT_IND_FINAL_RSP_STATE:
            cmd_code = L2CAP_CMD_CONFIG_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfResp(scid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CONFIG_RSP_STATE:
		    # ConfigResp(fail)
            cmd_code = L2CAP_CMD_CONFIG_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfResp(scid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CONFIG_RSP_STATE Dst Match is not working" 
        return pkt, cmd_code
    
class WAIT_CONTROL_IND_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere
    def Get_Tran_Packet(self, dst, dcid_value):
        if dst == L2CAP_OPEN_STATE:
            cmd_code = L2CAP_CMD_CONFIG_REQ
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConfReq(dcid=dcid_value)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CONTROL_IND_STATE Dst Match is not working"           
        return pkt, cmd_code
    
    def Get_M_Packet(self, dst, dcid_value):
        if dst == L2CAP_OPEN_STATE:
            # Send ConnReq to prompt the target to send ConfRsp (-> ConfRsp Success)
            cmd_code = L2CAP_CMD_CONFIG_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfReq(dcid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CONFIG_STATE:
            cmd_code = ""
            pkt = ""
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_CONTROL_IND_STATE Dst Match is not working"
        return pkt, cmd_code
    
class WAIT_FINAL_RSP_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere
      
    def Get_Tran_Packet(self, dst, dcid_value):
        if dst == L2CAP_OPEN_STATE:
            cmd_code = L2CAP_CMD_CONFIG_RSP
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConfResp(scid=dcid_value)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_FINAL_RSP_STATE Dst Match is not working"
        return pkt, cmd_code
    
    def Get_M_Packet(self, dst, dcid_value):
        if dst == L2CAP_OPEN_STATE:
            #Spec says ConfRsp was sent, but BUT L2fuzz send ConfReq
            cmd_code = L2CAP_CMD_CONFIG_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfResp(scid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CONFIG_STATE:
            cmd_code = L2CAP_CMD_CONFIG_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfResp(scid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_FINAL_RSP_STATE Dst Match is not working"
        return pkt, cmd_code

class WAIT_IND_FINAL_RSP_STATE(STATE):
    def __init__(self, name, IsThere):
        self.name = name
        self.IsThere = IsThere

    def Get_Tran_Packet(self, dst, dcid_value):
        if dst == L2CAP_WAIT_FINAL_RSP_STATE:
            cmd_code = L2CAP_CMD_CONFIG_REQ
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConfReq(dcid=dcid_value, flags = 0)
        elif dst == L2CAP_WAIT_CONTROL_IND_STATE:
            cmd_code = L2CAP_CMD_CONFIG_RSP
            pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_ConfResp(scid=dcid_value)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_IND_FINAL_RSP_STATE Dst Match is not working"
        return pkt, cmd_code
    def Get_M_Packet(self, dst, dcid_value):
        if dst == L2CAP_WAIT_CONFIG_STATE:
            cmd_code = ""
            pkt = ""
        elif dst == L2CAP_WAIT_FINAL_RSP_STATE:
            # Send ConfReq to make target send ConfigRsp to enter W_Final_RSP
            cmd_code = L2CAP_CMD_CONFIG_REQ
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfReq(dcid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        elif dst == L2CAP_WAIT_CONTROL_IND_STATE:
            # According to the Spec, ConfRsp is supposed to be sent, but L2fuzz sends ConfReq
            cmd_code = L2CAP_CMD_CONFIG_RSP
            p = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfResp(scid=dcid_value)
            pkt = Mutate_Packet(cmd_code, p)
        else:
            print(f"Dst : {dst}")
            assert False, "WAIT_IND_FINAL_RSP_STATE Dst Match is not working"
        return pkt, cmd_code
    

class L2CAP_StateMachine:

    #### States ####
    CURRENT_STATE = L2CAP_CLOSED_STATE
    # Basic States
    # self.closed_state = CLOSED_STATE(CLOSED_STATE)
    closed_state = CLOSED_STATE(L2CAP_CLOSED_STATE, True)
    open_state = OPEN_STATE(L2CAP_OPEN_STATE, True)
    wait_config_state = WAIT_CONFIG_STATE(L2CAP_WAIT_CONFIG_STATE, True)
    wait_connect_state = WAIT_CONNECT_STATE(L2CAP_WAIT_CONNECT_STATE, True)
    wait_connect_rsp_state = WAIT_CONNECT_RSP_STATE(L2CAP_WAIT_CONNECT_RSP_STATE, False)
    wait_disconnect_state = WAIT_DISCONNECT_STATE(L2CAP_WAIT_DISCONNECT_STATE, True)

    # Optional States (Alternative MAC/PHY enabled operation)
    wait_create_state = WAIT_CREATE_STATE(L2CAP_WAIT_CREATE_STATE, True)
    wait_create_rsp_state = WAIT_CREATE_RSP_STATE(L2CAP_WAIT_CREATE_RSP_STATE, False)
    wait_move_confirm_state = WAIT_MOVE_CONFIRM_STATE(L2CAP_WAIT_MOVE_CONFIRM_STATE, True)
    wait_move_state = WAIT_MOVE_STATE(L2CAP_WAIT_MOVE_STATE, True)
    wait_move_rsp_state = WAIT_MOVE_RSP_STATE(L2CAP_WAIT_MOVE_RSP_STATE, False)
    wait_confirm_rsp_state = WAIT_CONFIRM_RSP_STATE(L2CAP_WAIT_CONFIRM_RSP_STATE, False)

    # Configurateion States
    wait_send_config_state = WAIT_SEND_CONFIG_STATE(L2CAP_WAIT_SEND_CONFIG_STATE, True)
    wait_config_req_rsp_state = WAIT_CONFIG_REQ_RSP_STATE(L2CAP_WAIT_CONFIG_REQ_RSP_STATE, False)
    wait_config_req_state = WAIT_CONFIG_REQ_STATE(L2CAP_WAIT_CONFIG_REQ_STATE, False)
    wait_config_rsp_state = WAIT_CONFIG_RSP_STATE(L2CAP_WAIT_CONFIG_RSP_STATE, True)
    wait_control_ind_state = WAIT_CONTROL_IND_STATE(L2CAP_WAIT_CONTROL_IND_STATE, True)
    wait_final_rsp_state = WAIT_FINAL_RSP_STATE(L2CAP_WAIT_FINAL_RSP_STATE, True)
    wait_ind_final_rsp_state = WAIT_IND_FINAL_RSP_STATE(L2CAP_WAIT_IND_FINAL_RSP_STATE, True)
    CURRENT_STATE = L2CAP_CLOSED_STATE

    def update_Cluster_IsThere(self):
        Clusters = {
            "Closed": {
                "IsThere": False,
                "states": {
                    self.closed_state: self.closed_state.IsThere
                }
            },
            "Wait Connect": {                   # When Fuzzer is Master
                "IsThere": False,
                "states": {
                    self.wait_connect_state: self.wait_connect_state.IsThere
                }
            },
            "Wait Connect Rsp": {               # When Fuzzer is Slave
                "IsThere": False,
                "states": {
                    self.wait_connect_rsp_state: self.wait_connect_rsp_state
                }
            },
            "Wait Create": {                       # When Fuzzer is Master
                "IsThere": False,
                "states": {
                    self.wait_create_state: self.wait_create_state.IsThere
                }
            },
            "Wait Create Rsp": {               # When Fuzzer is Slave
                "IsThere": False,
                "states": {
                    self.wait_create_rsp_state: self.wait_create_rsp_state.IsThere
                }
            },
            "Wait Config": {
                "IsThere": False,
                "states": {
                    self.wait_config_state: self.wait_config_state.IsThere
                }
            },
            "Wait Send Config": {                       # When Fuzzer is Master
                "IsThere": False,
                "states": {
                    self.wait_send_config_state: self.wait_send_config_state.IsThere,
                    self.wait_config_rsp_state: self.wait_config_rsp_state.IsThere,
                    self.wait_ind_final_rsp_state: self.wait_ind_final_rsp_state.IsThere,
                    self.wait_final_rsp_state:self.wait_final_rsp_state.IsThere,
                    self.wait_control_ind_state: self.wait_control_ind_state.IsThere
                }
            },
            "Wait Config Req Rsp": {               # When Fuzzer is Slave
                "IsThere": False,
                "states": {
                    self.wait_config_req_rsp_state: self.wait_config_req_rsp_state.IsThere,
                    self.wait_config_req_state: self.wait_config_req_state.IsThere,
                    self.wait_ind_final_rsp_state: self.wait_ind_final_rsp_state.IsThere,
                    self.wait_final_rsp_state: self.wait_final_rsp_state.IsThere,
                    self.wait_control_ind_state: self.wait_control_ind_state.IsThere
                }
            },
            "Open": {
                "IsThere": False,
                "states": {
                    self.open_state: self.open_state.IsThere
                }
            },
            "Wait Move": {                       # When Fuzzer is Master
                "IsThere": False,
                "states": {
                    self.wait_move_state: self.wait_move_state.IsThere,
                    self.wait_move_confirm_state: self.wait_move_confirm_state.IsThere
                }
            },
            "Wait Move Rsp": {                       # When Fuzzer is Slave
                "IsThere": False,
                "states": {
                    self.wait_confirm_rsp_state: self.wait_confirm_rsp_state.IsThere,
                    self.wait_move_rsp_state: self.wait_move_rsp_state.IsThere
                }
            },
            "Wait Disconnect": {
                "IsThere": False,
                "states": {
                    self.wait_disconnect_state: self.wait_disconnect_state.IsThere
                }
            }
        }
        return Clusters


    def Set_IsThere_Clustered_State(self, capturedStateM):
        stateM = {}
        Cluster = self.update_Cluster_IsThere()
        for cluster, clusterinfo in Cluster.items():
            SetClusterinfo = {}
            Setstateinfo = {}
            #IsThere
            SetClusterinfo["IsThere"]=clusterinfo["IsThere"]
            # Cluster pkt capture
            if capturedStateM is False:
                SetClusterinfo["Capture"] = []
            elif cluster in capturedStateM:
                SetClusterinfo["Capture"] = capturedStateM[cluster]
            else:
                SetClusterinfo["Capture"] = []

            for state in clusterinfo["states"]:
                if state.IsThere:
                    SetClusterinfo["IsThere"] = True
                
                Setstateinfo[change_state2str(state.name)] = state.IsThere
            SetClusterinfo["states"] = Setstateinfo
            stateM[cluster] = SetClusterinfo
        return stateM
    
    def output_stateM(self, capturedStateM, Cluster):
        stateM = {}

        for cluster, clusterinfo in Cluster.items():
            SetClusterinfo = {}
            Setstateinfo = {}
            #IsThere
            SetClusterinfo["IsThere"]=clusterinfo["IsThere"]
            # Cluster pkt capture
            if cluster in capturedStateM:
                SetClusterinfo["Capture"] = capturedStateM[cluster]
            else: 
                SetClusterinfo["Capture"] = []
            #state IsThere
            for state in clusterinfo["states"]:
                Setstateinfo[change_state2str(state.name)] = state.IsThere

            SetClusterinfo["states"] = Setstateinfo
            stateM[cluster] = clusterinfo
        return stateM