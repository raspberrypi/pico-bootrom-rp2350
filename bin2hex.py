#!/usr/bin/env python3

import sys
import re

if __name__ == "__main__":
	if len(sys.argv) < 3:
		sys.exit("Usage: bin2hex.py [-<width>] <infile|-> <outfile|->\ne.g. bin2hex.py -32 rom.bin rom.hex")
	size = 32
	argn = 1;
	m = re.match(r"-(\d+)", sys.argv[argn])
	if m:
		size = int(m.group(1))
		argn = argn + 1

	if size <= 0 or size % 8 != 0:
		sys.exit("Size must be a multiple of 8 (got {})".format(size))

	if sys.argv[argn] == '-':
		ifile = sys.stdin.buffer
	else:
		ifile = open(sys.argv[argn], "rb")
		argn = argn + 1
	if sys.argv[argn] == '-':
		ofile = sys.stdout
	else:
		ofile = open(sys.argv[argn], "w")
	argn = argn + 1

	bytes_per_word = size // 8

	while True:
		bytes = ifile.read(bytes_per_word)
		if not bytes:
			break
		word = ''
		for i in range(bytes_per_word):
			word = ("%02X" % (bytes[i] if i < len(bytes) else 0)) + word
		ofile.write("%s\n" % word)

	ifile.close()
	ofile.close()
