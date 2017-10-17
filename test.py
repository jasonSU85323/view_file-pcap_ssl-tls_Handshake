#!/usr/bin/env python
#coding=utf-8

import dpkt

# definition
pcap_file = open('test.pcap', "rb")
pcap_file_data = pcap_file.read().encode('hex')
pcap_data = []
pcap_header = {}
pcap_packet = {}
pcap_packet_num = None

#-------HandshakeType
HandshakeType = {
	"01" : "Client Hello"		,
	"02" : "Server Hello"		,
	"11" : "Certificate" 		,
	"12" : "Server Key Exchange",
	"14" : "Server Hello Done"	,
	"16" : "Clien Key Exchange"
}

#-------ContentType
ContentType = {
	"16" : "Handshake"
}

#-------Version
Version = {
	"0300" : "SSL 3.0",
	"0301" : "TLS 1.0",
	"0302" : "TLS 1.1",
	"0303" : "TLS 1.2"
}

#------CipherSuite
CipherSuite = {
	"c02b" : "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"		,
	"c02f" : "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"		,
	"009e" : "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"			,
	"cc14" : "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	"cc13" : "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"	,
	"cc15" : "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"	,
	"c00a" : "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"			,
	"c014" : "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"			,
	"0039" : "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"				,
	"c009" : "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"			,
	"c013" : "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"			,
	"0033" : "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"				,
	"009c" : "TLS_RSA_WITH_AES_128_GCM_SHA256"				,
	"0035" : "TLS_RSA_WITH_AES_256_CBC_SHA"					,
	"002f" : "TLS_RSA_WITH_AES_128_CBC_SHA"					,
	"000a" : "TLS_RSA_WITH_3DES_EDE_CBC_SHA"				,
	"00ff" : "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
}

def print_pcap_data(pcap_data):
	print("pcap all  ot data (hex):")
	a = -1
	n = 1
	for i in pcap_data:
		a += 1
		if a%16 == 0:
			print("\n"),
			print(n),
			n += 1
		print(str(i) + " "),

	print("\n")

def print_pcap_header(pcap_header):
	print("pcap file header data (hex):")
	print("magic_number  : " + str(pcap_header['magic_number'])	 )
	print("version_major : " + str(pcap_header['version_major']) )
	print("version_minor : " + str(pcap_header['version_minor']) )
	print("version_minor : " + str(pcap_header['version_minor']) )
	print("sigfigs       : " + str(pcap_header['sigfigs'])		 )
	print("snaplen       : " + str(pcap_header['snaplen'])		 )
	print("linktype      : " + str(pcap_header['linktype'])		 )
	print("\n")

def print_pcap_packet(pcap_packet):
	print("pcap file header data (hex):")
	for i in range(1, pcap_packet_num+1):
		print("Number " + str(i) + " a pcap packet:")
		print("GMTtime   : " + str(pcap_packet[str(i) + '_GMTtime'])	  )
		print("MicroTime : " + str(pcap_packet[str(i) + '_MicroTime']) )
		print("caplen    : " + str(pcap_packet[str(i) + '_caplen'])	  )
		print("len       : " + str(pcap_packet[str(i) + '_len'])		  )
		print("data      : " + str(pcap_packet[str(i) + '_data'])	  )
		print("\n")

def ClientHello(data):
	#definition
	V  = "" 
	R  = ""
	CS = ""

	#title
	print("/*****ClientHello*****/")

	#Version
	V = Version[str(data[63]) + str(data[64])]
	print("Version              : " + V)

	#Random Bytes
	for i in range(69,97):
		R += data[i]
	print("Random Bytes         : " + R)
	
	#Cipher Suites
	CipherSuitesLength = int(data[98] + data[99], 16)
	print("CipherSuites (" + str(CipherSuitesLength/2) + " suites)")

	CipherName = ""
	for i in range(0,CipherSuitesLength,2):
		for j in range(0,2):
			CipherName += data[100+i+j]
		print("     CipherSuites : "),
		
		try:
			print(CipherSuite[str(CipherName)])
		except KeyError:
			print("(" + str(CipherName) + ") "),
			print("Unknown Encryption Kit!!")

		CipherName = ""

	#end
	print("")	

def ServerHello(data):
	#definition
	V  = "" 
	R  = ""
	CS = ""

	#title
	print("/*****ServerHello*****/")

	#Version
	V = Version[str(data[63]) + str(data[64])]
	print("Version              : " + V)

	#Random Bytes
	for i in range(69,97):
		R += data[i]
	print("Random Bytes         : " + R)
	
	#Cipher Suites
	CS = str(data[98]) + str(data[99])
	print("CipherSuites         :"),
	try:
		print(CipherSuite[CS])
	except KeyError:
		print("(" + CS + ") "),
		print("Unknown Encryption Kit!!")

	#end
	print("")

if __name__ == '__main__':
#---------------------------------------------------------------(1)從檔案取出16進位值，再加入pcap_data[]陣列裡
	a = 0
	b = ""
	for i in pcap_file_data:
		a += 1
		b += i
		if a == 2:
			pcap_data.append(b)
			a = 0
			b = ""
	# test_print
	# print_pcap_data(pcap_data)

#---------------------------------------------------------------(2)從pcap_data[]取出檔頭資料，再加入pcap_header{}字典裡
	pcap_header['magic_number'] = pcap_data[ 0: 4]
	pcap_header['version_major']= pcap_data[ 4: 6]
	pcap_header['version_minor']= pcap_data[ 6: 8]
	pcap_header['thiszone'] 	= pcap_data[ 8:12]
	pcap_header['sigfigs'] 		= pcap_data[12:16]
	pcap_header['snaplen'] 		= pcap_data[16:20]
	pcap_header['linktype'] 	= pcap_data[20:24]
	# test_print
	# print_pcap_header(pcap_header)

#---------------------------------------------------------------(3)從pcap_data[]取出封包資料，再加入pcap_packet_header{}字典裡
	packet_num = 1
	i =24
	while(i<len(pcap_data)):
	     
	    #數據包頭個個字段
	    pcap_packet[str(packet_num) + '_GMTtime']	= pcap_data[i     : i +  4]
	    pcap_packet[str(packet_num) + '_MicroTime'] = pcap_data[i +  4: i +  8]
	    pcap_packet[str(packet_num) + '_caplen'] 	= pcap_data[i +  8: i + 12]
	    pcap_packet[str(packet_num) + '_len'] 		= pcap_data[i + 12: i + 16]
	    
	    # 求出此包的包長len
	    packet_len = int(pcap_data[i+15] + pcap_data[i+14] + pcap_data[i+13] + pcap_data[i+12] ,16 )

	    pcap_packet[str(packet_num) + '_data'] 		= pcap_data[i + 16: i + packet_len + 16]

	    i = i+ packet_len+16
	    packet_num+=1

	pcap_packet_num = len(pcap_packet)/5
	# test_print
	# print_pcap_packet(pcap_packet)

#---------------------------------------------------------------(4)找出ClientHello與ServerHello
	for i in range(1, pcap_packet_num+1):
		data = pcap_packet[str(i) + '_data']

		try:
			v1 = str(data[55]) + str(data[56])
			v2 = str(data[63]) + str(data[64])
			h  = str(data[59])
			c  = str(data[54])
		except IndexError:
			pass
		else:
			# print(v1, v2, h, c)
			if Version.has_key(v1) and Version.has_key(v2) and HandshakeType.has_key(h) and ContentType.has_key(c):
				# print(str(i) + ": ")
				# print(v1, v2, h, c)
				if h in "01":
					ClientHello(data)
				elif h in "02":
					ServerHello(data)
				else:
					print("Error!! "),
					print("h = " + str(h))


		
		# print(str(i) + " : " + str(data[63:65]))

#---------------------------------------------------------------(E)完成
	print("----------------------------------")
	print("OK! Done!")
	print("pcap_packet to sum : " +  str(pcap_packet_num))
