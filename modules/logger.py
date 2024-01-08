import os, subprocess
import threading, queue
import logging
import json


class Logger:
	def __init__(self, time):
		self.time = time
		self.Q_crash_cnt = 0
		self.packet_Queue = queue.Queue()
		self.lock = threading.Lock()

		self.logger = logging.getLogger()
		self.logger.setLevel(logging.DEBUG)
		self.formatter = logging.Formatter(u'[%(levelname)8s] %(message)s')

		# Save splitted log file
		os.makedirs("./log/{}".format(self.time))
		self.tmp_pkt_cnt = 0
		self.savefile_version = 1
		self.current_savefile_path = "./log/{}/{}_v{}.log".format(self.time, self.time, self.savefile_version)

		self.file_handler = logging.FileHandler(self.current_savefile_path)
		self.file_handler.setFormatter(self.formatter)
		self.logger.addHandler(self.file_handler)

		self.start_time = 0
		self.end_time = 0


	def init_info(self, data):
		with open (self.current_savefile_path, 'a') as f:
			json.dump(data, f, indent=4)

	def inputQueue(self, log):
		self.packet_Queue.put(log)

	def logUpdate(self):
		print("[*] Start Update!")
		print("Queue Size : {}".format(self.packet_Queue.qsize()))
		self.lock.acquire()
		for _ in range(self.packet_Queue.qsize()):
			self.logger.debug(self.packet_Queue.get())
			self.tmp_pkt_cnt += 1
		self.lock.release()
		print("[*] Complete Update!")
		self.Q_crash_cnt = 0
		if self.tmp_pkt_cnt > 1000000:
			self.savefile_version += 1
			self.current_savefile_path = "./log/{}/{}_v{}.log".format(self.time, self.time, self.savefile_version)
			
			self.file_handler = logging.FileHandler(self.current_savefile_path)
			self.file_handler.setFormatter(self.formatter)
			self.logger.addHandler(self.file_handler)
			self.tmp_pkt_cnt = 0
		

def log_pkt(pkt):
	"""
	get default format of each packet and update the values
	"""
	pkt_default = dict(pkt.default_fields, **pkt.payload.default_fields)
	pkt_default = dict(pkt_default, **pkt.payload.payload.default_fields)
	pkt_CmdHdr_updated = dict(pkt_default, **pkt.fields)
	pkt_payload_updated = dict(pkt_CmdHdr_updated, **pkt.payload.fields)
	pkt_garbage_updated = dict(pkt_payload_updated, ** pkt.payload.payload.fields)
	
	return pkt_garbage_updated


def l2ping(bt_addr):
	"""
	<Crash finding example>
	1) Check the status of sockect in send() method
	2) If there is error in send(), Check l2ping
	3) if l2ping finds packet lost, it is crash!
	+ You need to check the target device's condition. (Error pop-up or crash dump.)
	"""
	l2pingRes = subprocess.run(['l2ping',str(bt_addr),"-c","3"],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	try:
		failureRate = str(l2pingRes.stdout).split()[-2]
		failureRate = int(failureRate.split("%")[0])
	except ValueError:
		failureRate = 100
	if(failureRate < 100):
		return True
	else:
		return False