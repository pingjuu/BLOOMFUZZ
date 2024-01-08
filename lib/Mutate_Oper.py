from random import randint, randrange, choices, choice
from scapy.layers.bluetooth import *

from lib.btpacket import *


def random_psm():
    """
    random psm for connection state fuzzing

    Since PSMs are odd and the least significant bit of the most significant byte is zero,
    the following ranges do not contain valid PSMs: 0x0100-0x01FF, 0x0300-0x03FF,
    0x0500-0x05FF, 0x0700-0x07FF, 0x0900-0x09FF, 0x0B00-0x0BFF, 0x0D00-
    0x0DFF. All even values are also not valid as PSMs.
    """
    # Get random invalid psm value
    psm4fuzz = 0
    opt = randint(0, 7)
    if(opt == 0):
        psm4fuzz = randrange(0x0100, 0x01FF + 0x0001)
    elif(opt == 1):
        psm4fuzz = randrange(0x0300, 0x03FF + 0x0001)
    elif(opt == 2):
        psm4fuzz = randrange(0x0500, 0x05FF + 0x0001)
    elif(opt == 3):
        psm4fuzz = randrange(0x0700, 0x07FF + 0x0001)
    elif(opt == 4):
        psm4fuzz = randrange(0x0900, 0x09FF + 0x0001)
    elif(opt == 5):
        psm4fuzz = randrange(0x0B00, 0x0BFF + 0x0001)
    elif(opt == 6):
        psm4fuzz = randrange(0x0D00, 0x0DFF + 0x0001)
    elif(opt == 7):
        psm4fuzz = randrange(0x0000, 0xFFFF + 0x0001, 2)	
    return psm4fuzz


def xor(a, b):
    return bytes(_a ^ _b for _a, _b in zip(a, b))

# len: 입력값의 길이 (단위: 바이트)
def bitflip(p: int, l: int) -> int:
    assert 0 <= p <= ((1 << (l * 8)) - 1) and l <= 2

    op = randint(0, 2 if l == 1 else 3)
    result = p.to_bytes(l, 'big')

    if op == 0:
        key = b'\xff' * l
    
    elif op == 1:
        if l == 1:
            key = b'\x81'
        else:
            key = b'\x80' + b'\x00' * (l - 2) + b'\x01'

    # 4/1
    elif op == 2:
        if l == 1:
            key = b'\xA5'
        else:
            key = b'\xA0' + b'\x00' * (l - 2) + b'\x05'

    # 16/8
    elif op == 3:
        assert l == 2
        key = b'\xff\x00'

    else:
        assert False

    result = xor(result, key)

    result = int.from_bytes(result, byteorder='big')
    return result

def arithmetic(p: int, l: int) -> int:
    assert 0 <= p <= ((1 << (l * 8)) - 1) and l <= 2

    op = randint(0, 0 if l == 1 else 1)
    inc_or_dec = randint(0, 1)

    # 8/8
    if op == 0:
        if l == 1:
            if inc_or_dec:
                p += 1
            else:
                p -= 1
            p = p % ((1 << (l * 8)))
        else:
            hb = p // 0x100
            lb = p % 0x100
            if inc_or_dec:
                hb += 1
                lb += 1
            else:
                hb -= 1
                lb -= 1
            hb = hb % ((1 << ((l - 1) * 8)))
            p = (hb << ((l - 1) * 8)) | lb

    # 16/8
    elif op == 1:
        if inc_or_dec:
            p += 1
        else:
            p -= 1
        p = p % (1 << (l * 8))
    else:
        assert False

    return p

def random_byte(p: int, l: int) -> int:
    assert 0 <= p <= ((1 << (l * 8)) - 1) and l <= 2
    
    if l == 1:
        p = randrange(0x00, 0x100) 

    elif l == 2:
        hb = p // 0x100
        lb = p % 0x100

        op = randint(0, 2)

        # randomize hb
        if op == 0:
            p = (randrange(0x00, 0x100) << 8) | lb
        # randomize lb
        elif op == 1:
            p = (hb << 8) | (randrange(0x00, 0x100))
        else:
            p = randrange(0x00, 0x10000)

    else:
        assert False

    return p

def zero_padding(p: int, l: int) -> int:
    assert 0 <= p <= ((1 << (l * 8)) - 1) and l <= 2
    return 0

def crossover(p: int, l: int) -> int:
    assert 0 <= p <= ((1 << (l * 8)) - 1) and l <= 2
    if l == 1:
        hhb = p // 0x10
        lhb = p % 0x10
        p = (lhb << 4) | hhb
    else:
        hb = p // 0x100
        lb = p % 0x100
        p = (lb << 8) | hb
    return p


def gen_param(origin, bytelen, condition):

    opers = [bitflip, arithmetic, random_byte, zero_padding, crossover]
    oper_idx = randrange(0, len(opers))
    result = opers[oper_idx](origin, bytelen)
    while (1):
        oper_idx = randrange(0, len(opers))
        result = opers[oper_idx](origin, bytelen)
        if (condition[0] <= result < condition[1]):
            break
    return result


def gen_garvage_field_payload():
    # randin ir zero padding
    # TODO zero padding 1퍼 확률로 나오게 구현하기
    max_byte_len = 2
    data = randrange(0x00, 0x10000)

    data = data.to_bytes(max_byte_len, 'little')
    p_len = randrange(0, max_byte_len + 1)
    result = data[:p_len]
    result = int.from_bytes(result, 'little')
    return result

def gen_edge(min, max):
    edge_min = choice(min -1, min, min+1)
    edge_max = choice(max-1, max, max+1)
    return edge_min, edge_max

def Mutate_Packet(cmd_code, origin_pkt): # cmd_code : mutate 할 packet 종류
    operand = choices(range(0, 2), weights = [0.1, 0.9])
    
    if operand:
        ran_garbage = gen_garvage_field_payload()
        pkt = origin_pkt/garbage_value(garbage=ran_garbage)
        if cmd_code in [0x02, 0x0C]:
            ran_psm = random_psm()
            if cmd_code == 0x02:
                pkt = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConnReq(psm=ran_psm)/garbage_value(garbage=ran_garbage)
            else:
                pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Create_Channel_Request(psm=ran_psm)/garbage_value(garbage=ran_garbage)
        elif cmd_code in [0x03, 0x06, 0x07, 0x0D]:
            ran_scid = gen_param(origin_pkt[1].scid, 2, (0x0040, 0x10000))
            ran_dcid = gen_param(origin_pkt[1].dcid, 2, (0x0040, 0x10000))
            if cmd_code == 0x03:
                pkt = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConnResp(dcid=ran_dcid, scid=ran_scid)/garbage_value(garbage=ran_garbage)
            elif cmd_code == 0x06:
                pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_DisconnReq(scid=ran_scid, dcid=ran_dcid)/garbage_value(garbage=ran_garbage)
            elif cmd_code == 0x07:
                pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_DisconnResp(scid=ran_scid, dcid=ran_dcid)/garbage_value(garbage=ran_garbage)
            else:
                pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Create_Channel_Response(scid=ran_scid, dcid=ran_dcid)/garbage_value(garbage=ran_garbage)
        elif cmd_code in [0x04, 0x05]:
            if cmd_code == 0x04:
                ran_dcid = gen_param(origin_pkt[1].dcid, 2, (0x0040, 0x10000))
                pkt = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfReq(dcid=ran_dcid)/garbage_value(garbage=ran_garbage)
            elif cmd_code == 0x05:
                ran_scid = gen_param(origin_pkt[1].scid, 2, (0x0040, 0x10000))
                pkt = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfResp(scid=ran_scid)/garbage_value(garbage=ran_garbage)
        elif cmd_code in [0x0F, 0x10, 0x11]:
            ran_icid = gen_param(origin_pkt[1].icid, 1, (0x00, 0x100))
            if cmd_code == 0x0F:
                pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Response(icid=ran_icid)/garbage_value(garbage=ran_garbage)
            elif cmd_code == 0x10:
                pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Confirmation_Request(icid=ran_icid)/garbage_value(garbage=ran_garbage)
            else:
                pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Confirmation_Response(icid=ran_icid)/garbage_value(garbage=ran_garbage)
        elif cmd_code == 0x0E:
            ran_dest_controller_id = gen_param(origin_pkt[1].dest_controller_id, 1, (0x02, 0x100))
            pkt = L2CAP_CmdHdr(code=0x0E)/L2CAP_Move_Channel_Request(dest_controller_id=ran_dest_controller_id)/garbage_value(garbage=ran_garbage)
        else:
            print(cmd_code)
        return pkt
    else:
        #edge case operator
        ran_garbage = gen_garvage_field_payload()
        if cmd_code in [0x02, 0x0C]:
            ran_psm = random_psm()
            if cmd_code == 0x02:
                pkt = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConnReq(psm=ran_psm)/garbage_value(garbage=ran_garbage)
            else:
                pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Create_Channel_Request(psm=ran_psm)/garbage_value(garbage=ran_garbage)
        elif cmd_code in [0x03, 0x06, 0x0D]:
            ran_scid = gen_edge(0x0040, 0xFFFF)
            ran_dcid = gen_edge(0x0040, 0xFFFF)
            if cmd_code == 0x03:
                pkt = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConnResp(dcid=ran_dcid, scid=ran_scid)/garbage_value(garbage=ran_garbage)
            elif cmd_code == 0x06:
                pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_DisconnReq(scid=ran_scid, dcid=ran_dcid)/garbage_value(garbage=ran_garbage)
            else:
                pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Create_Channel_Response(scid=ran_scid, dcid=ran_dcid)/garbage_value(garbage=ran_garbage)
        elif cmd_code in [0x04, 0x05]:
            if cmd_code == 0x04:
                ran_dcid = gen_edge(0x0040, 0xFFFF)
                pkt = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfReq(dcid=ran_dcid)/garbage_value(garbage=ran_garbage)
            elif cmd_code == 0x05:
                ran_scid = gen_edge(0x0040, 0xFFFF)
                pkt = L2CAP_CmdHdr(code=cmd_code)/new_L2CAP_ConfResp(scid=ran_scid)/garbage_value(garbage=ran_garbage)
        elif cmd_code in [0x0F, 0x10, 0x11]:
            ran_icid = gen_edge(0x00, 0x100)
            if cmd_code == 0x0F:
                pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Response(icid=ran_icid)/garbage_value(garbage=ran_garbage)
            elif cmd_code == 0x10:
                pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Confirmation_Request(icid=ran_icid)/garbage_value(garbage=ran_garbage)
            else:
                pkt = L2CAP_CmdHdr(code=cmd_code)/L2CAP_Move_Channel_Confirmation_Response(icid=ran_icid)/garbage_value(garbage=ran_garbage)
        elif cmd_code == 0x0E:
            pkt = L2CAP_CmdHdr(code=0x0E)/L2CAP_Move_Channel_Request(dest_controller_id=gen_edge(0x02, 0xFF))/garbage_value(garbage=ran_garbage)
