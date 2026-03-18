#!/usr/bin/env python

import sys
import struct

for i in range(1, len(sys.argv), 2):
	if sys.argv[i] == "-s":
		shellcode = sys.argv[i+1].encode().decode("unicode_escape").encode("latin-1")
	elif sys.argv[i] == "-h":
		print("Usage : ./AsciiEncode.py <args>\n-s - '<Shellcode>'")
	else:
		print("Invalid Args\nUsage : ./AsciiEncode.py <args>\n-s - '<Shellcode>'")

adds = False

eshellcode = b''

eaxa = b''
eaxb = b''
eaxc = b''

if len(shellcode)%4 != 0:
	adjust = 4-(len(shellcode)%4)
	shellcode += b'\x90'*adjust
	rsc = bytes(reversed(shellcode))
	for i in range(int(len(rsc)/4)):
		sc = rsc[:4]
		rsc = rsc[4:]
		eshellcode += b'\x25\x40\x40\x40\x40\x25\x04\x04\x04\x04'
		for b in sc:
			if b == 255:
				adds = True
				eaxa = b''
				eaxb = b''
				for b in sc:
					mod = b%3
					ei = int((b-mod)/3)
					eb = int((b-mod)/3).to_bytes(1, "big")
					eaxa+=eb
					eaxb+=eb
					if mod != 0:
						mi = ei+mod
						mb = mi.to_bytes(1, "big")
						eaxc+=mb
					else:
						eaxc+=eb
			elif not(adds):
				mod = b%2
				ei = int((b-mod)/2)
				eb = int((b-mod)/2).to_bytes(1, "big")
				eaxa+=eb
				if mod != 0:
					mi = ei+mod
					mb = mi.to_bytes(1, "big")
					eaxb+=mb
				else:
					eaxb+=eb
		if not(adds):
			eshellcode += b'\x05'
			eshellcode += bytes(reversed(eaxa))
			eshellcode += b'\x05'
			eshellcode += bytes(reversed(eaxb))
			eshellcode += b'\x50'
		else:
			eshellcode += b'\x05'
			eshellcode += bytes(reversed(eaxa))
			eshellcode += b'\x05'
			eshellcode += bytes(reversed(eaxb))
			eshellcode += b'\x05'
			eshellcode += bytes(reversed(eaxc))
			eshellcode += b'\x50'
		adds = False	
		eaxa = b''
		eaxb = b''
		eaxc = b''

seshellcode = ''.join(f'\\x{b:02x}' for b in eshellcode)
print(seshellcode)

sizereq = len(shellcode)+len(eshellcode)
print(f"Minimum memory required to properly execute shellcode: {sizereq} (Note : Memory required can differ considering multiple factors and nature of execution of this shellcode)")