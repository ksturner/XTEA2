#!/usr/bin/env python
import os, sys, getopt, random, getpass, hashlib, tarfile
import xtea2

#-------------------------------------------------------------------------------
def getPassword(prompt):
	""" Get a password from the user using the terminal. """
	password = getpass.getpass(prompt).strip()

	if len(password) > 16:
		password = password[:16]
	elif len(password) < 16:
		password = password + ' '*(16-len(password))
	return password

#-------------------------------------------------------------------------------
def generateRandomIV():
	iv = hashlib.sha1(str(random.random())).digest()
	return iv[:8]

#-------------------------------------------------------------------------------
def displayError(msg, errorTitle="Error"):
	if len(errorTitle) > 0:
		errorTitle = errorTitle.upper()
		print errorTitle+':', 
	print msg 


#-------------------------------------------------------------------------------
def encryptFile(fullfilepath):
	(filepath, filename) = os.path.split(fullfilepath)
	(filebase, fileext) = os.path.splitext(filename)
	if fileext.lower() == '.box':
		displayError("You can not encrypt a file with this suffix!")
		return False

	if os.path.exists(fullfilepath):
		password1 = getPassword("Enter a password: ")
		password2 = getPassword("Enter same password once more: ")
		if password1 != password2:
			displayError("Passwords did not match!")
			return False
	else:
		displayError("%s does not exist!" % (fullfilepath,))
		return False

	fullfilepath_hex = hashlib.md5(fullfilepath).hexdigest() + '.enc'
	filemapping = { }
	filemapping[fullfilepath_hex ] = fullfilepath

	if len(filepath.strip()) > 0:
		newfilename = filepath + os.sep + fullfilepath_hex 
	else:
		newfilename = fullfilepath_hex

	if os.path.exists(newfilename):
		displayError("Can't create %s, since it already exists!" % newfilename)
		return False

	# generate a new, random iv value
	iv = generateRandomIV() #xtea2.getRandomIV()
	ivhex = iv.encode('hex')

	# encrypt the user's file
	xtea2.cryptfile(fullfilepath, newfilename, password1, iv, 64)

	# open plaintext iv file, and write contents; encrypt it and remove the
	# original
	f = open(ivhex+'2.iv', 'w')
	f.write(fullfilepath_hex + '|' + fullfilepath+'\n')
	f.close()
	xtea2.cryptfile(ivhex+'2.iv', ivhex+'.iv', password1, iv, 64)
	os.remove(ivhex+'2.iv')

	# collect the iv file, and the encrypted file into a single zip file
	if len(filepath.strip()) > 0:
		newzipfile = filepath + os.sep + filebase + '.box'
	else:
		newzipfile = filebase + '.box'

	tar = tarfile.open(newzipfile, "w:bz2")
	tar.add(ivhex+'.iv')
	tar.add(fullfilepath_hex)
	tar.close()

	# cleanup files by removing encrypted iv file and user's file
	os.remove(ivhex+'.iv')
	os.remove(fullfilepath_hex)
	os.remove(fullfilepath)
	return True

#-------------------------------------------------------------------------------
def decryptFile(fullfilepath):
	(filepath, filename) = os.path.split(fullfilepath)
	(filebase, fileext) = os.path.splitext(filename)

	if not os.path.exists(fullfilepath):
		displayError("%s does not exist!" % (fullfilepath,))
		return False

	if fileext.lower() != '.box':
		displayError("You can not decrypt a file with this suffix!")
		return False
	elif not tarfile.is_tarfile(fullfilepath):
		msg = "You can not decrypt this file type!"
		return False

	password1 = getPassword("Enter a password: ")

	# Unzip the zip file to get the files within.
	iv = ''
	filemapping = { }
	tar = tarfile.open(fullfilepath, 'r:bz2')
	tar.extractall()
	tar.close()
	password_ok= False
	for n in os.listdir(os.curdir):
		(nfpath, nfname) = os.path.split(n)
		if nfname.endswith('.iv'):
			(filebase, fileext) = os.path.splitext(n)
			ivhex = filebase.strip()
			iv = ivhex.decode('hex')

			xtea2.cryptfile(nfname, filebase+'2.iv', password1, iv, 64)

			f = open(filebase+'2.iv', 'r')
			for line in f:
				if len(line.strip()) > 0 and "|" in line:
					password_ok = True
					(tempfname, realfname) = line.split("|")			
					tempfname = tempfname.strip()
					realfname = realfname.strip()
					filemapping[tempfname] = realfname
			f.close()

			os.remove(n)
			os.remove(filebase+'2.iv')

	# Now we need to translate all the file names to the real file names
	for (old,new) in filemapping.iteritems():
		xtea2.cryptfile(old, new, password1, iv, 64)
		os.remove(old)	

	# remove the zip(box) file
	if password_ok:
		os.remove(fullfilepath)
	else:
		# We need to loop over all files that were extracted from the tar file and 
		# make sure they are deleted if they still exist at this point.
		tar = tarfile.open(fullfilepath, 'r:bz2')
		for tarinfo in tar:
			if os.path.exists(tarinfo.name):
				os.remove(tarinfo.name)
		tar.close()
		return False
	return True

#-------------------------------------------------------------------------------
if __name__ == '__main__':
	random.seed()
	if sys.argv[1:]:
		try: 
			opts, args = getopt.getopt(sys.argv[1:], "d:e:h", ["decrypt=","encrypt=","help"])
		except getopt.error, msg:
			print msg
			print "for help use --help"
			sys.exit(2)
		for o, a in opts:
			if o in ('-h', '--help'):
				print __doc__
				sys.exit(0)
			elif o in ('-d','--decrypt'):
				fname = a
				success = decryptFile(fname)
				if success:
					msg = "%s was successfully decrypted!" % (fname,)
					msg_title = 'Finished'
				else:
					msg = "%s was NOT decrypted!" % (fname,)
					msg_title = 'Error'
				displayError(msg, msg_title)
				
			elif o in ('-e','--encrypt'):
				fname = a
				success = encryptFile(fname)
				if success:
					msg = "%s was successfully encrypted!" % (fname,)
					msg_title = 'Finished'
				else:
					msg = "%s was NOT encrypted!" % (fname,)
					msg_title = 'Error'
				displayError(msg, msg_title)
			
		
