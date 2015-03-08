## tbwunzip reads from a password file in an attempt to crack the password on a password protected zip archive
## it also reports on passwords that pass the initial checksum but fail when attempting to read data
## it also allows you to extract the file if it determines it found the correct password
## it needs to be run in the same directory as the archive
## the code is mostly just an elaboration of the code from zipfile library built into Python
## logging into is output to a file named "pwlog.txt"
## syntax: tbwunzip [archive] [password file]
## example: tbwunzip myarchive.zip passwords.txt

import sys, zipfile, os, shutil , io, struct, zlib  

archive = sys.argv[1]
pwfile = sys.argv[2]

myzip =  zipfile.ZipFile(archive, 'r')
f = open(pwfile ,'r')
l = open('pwlog.txt','w')

print("attempting the following passwords...")
for pw in f.read().split('\n'):
	try:
		print(pw)
		pwd = pw.encode("utf-8")
		# myzip.extractall(path, myzip.namelist(), pwd)     ## this single command will unzip all files in an archive if the correct pwd is provided
		#	The code below mainly expands it out and provides some other options
		for zipinfo in myzip.namelist():
			path = os.getcwd()
			# myzip.extract(zipinfo, path, pwd)     ## extractall calls this to extract an individual file from the archive	
			# myzip._extract_member(member, path, pwd)     ## extract calls this
			member = myzip.getinfo(zipinfo)
			
			arcname = member.filename.replace('/', os.path.sep)
			if os.path.altsep:
				arcname = arcname.replace(os.path.altsep, os.path.sep)
			arcname = os.path.splitdrive(arcname)[1]
			invalid_path_parts = ('', os.path.curdir, os.path.pardir)
			arcname = os.path.sep.join(x for x in arcname.split(os.path.sep) if x not in invalid_path_parts)
			if os.path.sep == '\\':
				arcname = myzip._sanitize_windows_name(arcname, os.path.sep)

			path = os.path.join(path, arcname)
			path = os.path.normpath(path)
			
			upperdirs = os.path.dirname(path)
			if upperdirs and not os.path.exists(upperdirs):
				os.makedirs(upperdirs)
 
			if member.filename[-1] == '/':
				if not os.path.isdir(path):
					os.mkdir(path)
 
			# with myzip.open(member, pwd=pwd) as source, open(path, "wb") as target:     ## _extract_member calls this
			#	shutil.copyfileobj(source, target)     ## _extract_member calls this to actually read the file out of the archive
			
			target = open(path, "wb")
			mode="r"
			if pwd and not isinstance(pwd, bytes):
				raise TypeError("pwd: expected bytes, got %s" % type(pwd))
			if not myzip.fp:
				raise RuntimeError(
					"Attempt to read ZIP archive that was already closed")
			if myzip._filePassed:
				zef_file = myzip.fp
			else:
				zef_file = io.open(myzip.filename, 'rb')
			
			try:
				if isinstance(member, zipfile.ZipInfo):
					zinfo = member
				else:
					zinfo = myzip.getinfo(member)
				zef_file.seek(zinfo.header_offset, 0)

				fheader = zef_file.read(zipfile.sizeFileHeader)
				if len(fheader) != zipfile.sizeFileHeader:
					raise BadZipFile("Truncated file header")
				fheader = struct.unpack(zipfile.structFileHeader, fheader)
				if fheader[zipfile._FH_SIGNATURE] != zipfile.stringFileHeader:
					raise BadZipFile("Bad magic number for file header")

				fname = zef_file.read(fheader[zipfile._FH_FILENAME_LENGTH])
				if fheader[zipfile._FH_EXTRA_FIELD_LENGTH]:
					zef_file.read(fheader[zipfile._FH_EXTRA_FIELD_LENGTH])

				if zinfo.flag_bits & 0x20:
					raise NotImplementedError("compressed patched data (flag bit 5)")

				if zinfo.flag_bits & 0x40:
					raise NotImplementedError("strong encryption (flag bit 6)")
					
				if zinfo.flag_bits & 0x800:
					fname_str = fname.decode("utf-8")
				else:
					fname_str = fname.decode("cp437")

				if fname_str != zinfo.orig_filename:
					raise BadZipFile(
						'File name in directory %r and header %r differ.'
						% (zinfo.orig_filename, fname))

				is_encrypted = zinfo.flag_bits & 0x1
				zd = None
				if is_encrypted:
					if not pwd:
						pwd = myzip.pwd
					if not pwd:
						raise RuntimeError("File %s is encrypted, password required for extraction" % member)

					zd = zipfile._ZipDecrypter(pwd)
					header = zef_file.read(12)
					h = list(map(zd, header[0:12]))
					
					if zinfo.flag_bits & 0x8:
						check_byte = (zinfo._raw_time >> 8) & 0xff
					else:
						check_byte = (zinfo.CRC >> 24) & 0xff
					if h[11] == check_byte:
						l.write ("Potential password based on check_byte match: %s\n" % check_byte)
						#shutil.copyfileobj(source, target)     ## _extract_member calls this to actually read the file out of the archive
						source = zipfile.ZipExtFile(zef_file, mode, zinfo, zd, close_fileobj=not myzip._filePassed)
						length=16*1024
						try:
							## try to use the password to read from the file
							buf = source.read(length)
							## if no exception then continue
							l.write("\t!!! Successfully able to read from file using password \'%s\'\n" % pw)
							x = input("\nSuccessfully able to read from file using password \'%s\'.\nPress \'X\' to stop and exit.\nPress \'Y\' to unzip the file and exit.\nPress any other any other key to continue...\n" % pw)
							if x in ('x','X'):
								myzip.close()
								f.close()
								l.close()
								sys.exit(0)
								
							## The code below will actually extract the file. It can be quite slow. It comes from shutil.copyfileobj
							if x in ('y','Y'):
								print("\tAttempting to unzip the file...")
								try:
									while 1:
										buf = source.read(length)
										if not buf:
											break
										target.write(buf)
								except:
									raise RuntimeError("Error extracting file", member,zz)
								myzip.close()
								f.close()
								l.close()
								sys.exit(0)
						except zlib.error as e:
							l.write("\tError using \'%s\'. It may not be the actual password. Error: %s\n" % (pw, e))
					else:
						if mode == 2:
							raise RuntimeError("Bad password for file", member)
			except:
				if not myzip._filePassed:
					zef_file.close()
				raise	
	except RuntimeError as e:
		l.write("\terror %s\n" % e)
myzip.close()
f.close()
l.close()
sys.exit(0)