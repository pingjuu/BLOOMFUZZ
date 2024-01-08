from scapy.all import rdpcap
from scapy.layers.bluetooth import *
from collections import OrderedDict, defaultdict

def Parse_L2Sig_Pkt(pkt_path):
    pkts = rdpcap(pkt_path)
    captured_pkt = OrderedDict()
    index = 0
    for i, pkt in enumerate(pkts):
        if pkt.getfieldval("direction") == 0:        # 0-outgoing, 1-incoming
            hcipkt = pkt[1]
            if hcipkt.type == 0x02:
                hci_aclpkt = hcipkt[1]
                if hci_aclpkt.PB == 0:
                    l2cap_pkt = hci_aclpkt[1]
                    if l2cap_pkt.cid == 1:
                    # l2cap signal packet
                        code = l2cap_pkt.code
                        if code in [0x01, 0x08, 0x09, 0x0A, 0x0B]:
                            continue
                        captured_pkt[index] = l2cap_pkt.code
                        index += 1
    return captured_pkt


def classifyStateM(stateMs):
    cluster_stateMs = {
        "Wait Connect":[],
        "Wait Connect Rsp":[],
        "Wait Send Config":[],
        "Wait Config Req Rsp":[],
        "Wait Create":[],
        "Wait Create Rsp":[],
        "Wait Move": [],
        "Wait Move Rsp":[],
        "Wait Disconnect":[]
    }
    for cluster_num in stateMs.keys():
        if cluster_num in [0x02, 0x03]:
            cluster_stateMs["Wait Connect"].extend(stateMs[cluster_num])
        elif cluster_num == 0x04:
            cluster_stateMs["Wait Send Config"].extend(stateMs[cluster_num])
        elif cluster_num == 0x05:
            cluster_stateMs["Wait Config Req Rsp"].extend(stateMs[cluster_num])
        elif cluster_num in [0x0C, 0x0D]:
            cluster_stateMs["Wait Create"].extend(stateMs[cluster_num])
        elif cluster_num in [0x0E, 0x0F]:
            cluster_stateMs["Wait Move"].extend(stateMs[cluster_num])
        elif cluster_num in [0x06, 0x07]:
            cluster_stateMs["Wait Disconnect"].extend(stateMs[cluster_num])
    return cluster_stateMs


def Reconstruct_StateM2(captured_pkt):
    # 단일 cluster도 적용해야한다.
    cmd_code2cluster = {
        0x2: 0,
        0x3: 0,
        0x4: 1,
        0x5: 1,
        0x6: 2,
        0x7: 2,
        0xC: 3,
        0xD: 3,
        0xE: 4,
        0xF: 4,
        0x10: 4,
        0x11: 4,
    }

    clusters = []
    cluster = []
    current_cluster = -1

    for pkt_info in captured_pkt.items():
        _, cmd_code = pkt_info

        cluster_id = cmd_code2cluster.get(cmd_code, -1)

        # 클러스터가 없는 cmd_code 인 경우
        if cluster_id == -1:
            continue

        # 최초 클러스터인 경우
        if current_cluster == -1:
            current_cluster = cluster_id
            cluster.append(cmd_code)

        # 최초 클러스터가 아닌 경우
        else:
            # 이전 클러스터와 같은 경우
            if current_cluster == cluster_id:
                cluster.append(cmd_code)
            
            # 이전 클러스터와 다른 경우
            else:
                clusters.append(tuple(cluster))
                current_cluster = cluster_id
                cluster = [cmd_code]
    
    if cluster != []:
        clusters.append(tuple(cluster))
    clusters = list(set(clusters))

    StateMs = defaultdict(list)
    for cluster in clusters:
        StateMs[cluster[0]].append(cluster)
    classifiedStateMs = classifyStateM(StateMs)
    return classifiedStateMs


def CommCapture(CommCapture_Path):
    if CommCapture_Path:
        captured_pkt = Parse_L2Sig_Pkt(CommCapture_Path)
        classifiedStateMs = Reconstruct_StateM2(captured_pkt)
        return classifiedStateMs
    else: return False


# if __name__== "__main__": 
#     CommCapture_Path = "/home/pingjuu/Bloom/CommCapture/pixel3.pcapng"
#     stateMs = CommCapture(CommCapture_Path)

