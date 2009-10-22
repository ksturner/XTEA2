
from distutils.core import setup, Extension

module1 = Extension('xtea2', sources=['xtea2module.c'])
setup(
	name="xtea2", 
	version="1.0",
	description="Efficient implementation of XTEA encryption algorithm.",
    author="Kevin Turner",
    author_email="kevin@ksturner.com",
    license="GPL v3",
	ext_modules=[module1])
