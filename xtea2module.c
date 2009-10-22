#include <Python.h>
#include <stdint.h>
#include <stdlib.h>

static PyObject *Xtea2Error;
static PyObject* xtea2_getrandomiv(PyObject *self, PyObject *args); 
static PyObject* xtea2_crypt(PyObject *self, PyObject *args); 
static PyObject* xtea2_cryptfile(PyObject *self, PyObject *args); 
static PyObject* xtea2_encipher(PyObject *self, PyObject *args);
static PyObject* xtea2_decipher(PyObject *self, PyObject *args); 
static void encipher(unsigned int num_rounds, uint32_t* v, uint32_t* k); 
static void encipher2(uint32_t num_rounds, uint32_t* v, uint32_t* k); 
static void decipher(uint32_t num_rounds, uint32_t* v, uint32_t* k); 
static void decipher2(uint32_t num_rounds, uint32_t* v, uint32_t* k); 

static PyMethodDef Xtea2Methods[] = {
	{ "crypt", xtea2_crypt, METH_VARARGS, "Encrypt/decrypt data."},
	{ "cryptfile", xtea2_cryptfile, METH_VARARGS, "Encrypt/decrypt files."},
	{ "getRandomIV", xtea2_getrandomiv, METH_VARARGS, "Gets random IV string."},
	{ "encipher", xtea2_encipher, METH_VARARGS, "Encrypt data."},
	{ "decipher", xtea2_decipher, METH_VARARGS, "Decrypt data."},
	{ NULL, NULL, 0, NULL}	/* Sentinel */
};

/*----------------------------------------------------------------------------*/
PyMODINIT_FUNC initxtea2(void) {
	PyObject *m;
	m = Py_InitModule("xtea2", Xtea2Methods);
	if (m == NULL) {
		return;
	}
	Xtea2Error = PyErr_NewException("xtea2.error", NULL, NULL);
	Py_INCREF(Xtea2Error);
	PyModule_AddObject(m, "error", Xtea2Error);
	srand(clock());
}

/*----------------------------------------------------------------------------*/
static PyObject* xtea2_getrandomiv(PyObject *self, PyObject *args) {
	uint8_t *placeholder;
	uint8_t *pointers[100];
	uint8_t iv[8];
	uint32_t i, len=0;
	PyObject *resultString;

	for (i=0; i<100; i++) {
		len = 0;
		while (len < 8) {
			len = (uint32_t)(rand() % 255); 
		}
		pointers[i] = malloc(len);
	}
	placeholder = pointers[rand()%100];

	if (placeholder != NULL) {
		for (i=0; i<8; i++) {
			iv[i] = *placeholder;
			placeholder++;
		}
	}
	resultString = Py_BuildValue("s#", iv, 8);
	for (i=0; i<100; i++) {
		free(pointers[i]);
	}
	return resultString;
}

/*----------------------------------------------------------------------------*/
static PyObject* xtea2_crypt(PyObject *self, PyObject *args) {
	uint8_t *newdata;
	uint8_t *key;
	int n = 0, i = 0;
	size_t counter = 0, len = 0;
	uint8_t buffer[8];
	uint8_t buffer2[8];
	uint8_t *input_buffer;
	uint8_t iv[8];
	uint8_t *s1;
	size_t s1len = 0;
	PyObject *resultString;

	if (!PyArg_ParseTuple(args, "s#ssi", &s1, &s1len, &key, &iv, &n)) {
		return NULL;
	}

	len = s1len;
	newdata = malloc(len);
	if (newdata == NULL) return NULL;
	memcpy((uint8_t*)newdata, (uint8_t*)s1, (size_t)len);

	input_buffer = iv;
	for (counter=0; counter < len; counter+=8) {
		encipher2((uint32_t)n, (uint32_t*)input_buffer, (uint32_t*)key);

		memcpy((uint8_t*)buffer, (uint8_t*)(newdata + counter), (size_t)8);
		for(i=0;i<8;i++) {
			buffer2[i] = (uint8_t)buffer[i] ^ (uint8_t)input_buffer[i]; 
		} 
		memcpy((uint8_t*)(newdata + counter), (uint8_t*)buffer2, (size_t)8);
	}

	resultString = Py_BuildValue("s#", newdata, len);
	free(newdata);
	return resultString;
}

/*----------------------------------------------------------------------------*/
/* cryptfile(infilename, outfilename, password, iv, rounds) */
static PyObject* xtea2_cryptfile(PyObject *self, PyObject *args) {
	FILE *fd_in, *fd_out;
	uint32_t n = 0, i = 0, len = 0;
	size_t bytes_read = 0;
	uint8_t buffer[8];
	uint8_t buffer2[8];
	uint8_t *input_buffer;
	uint8_t *f1, *f2, *iv, *key;

	if (!PyArg_ParseTuple(args, "ssss#I", &f1, &f2, &key, &iv, &len, &n)) {
		return NULL;
	}
	if((fd_in = fopen((char*)f1,"rb")) == NULL) {
		return NULL;
	}
	if((fd_out = fopen((char*)f2, "wb+")) == NULL) {
	 	return NULL;
	}

	input_buffer = malloc(len+1);
	if (!input_buffer) return NULL;
	memcpy((uint8_t*)input_buffer, (uint8_t*)iv, len); 

	bytes_read = fread((uint8_t*)buffer, sizeof(uint8_t), 8, fd_in);
	while (bytes_read > 0) {
		encipher2((uint32_t)n, (uint32_t*)input_buffer, (uint32_t*)key);
		for(i=0;i<8;i++) {
			buffer2[i] = (uint8_t)buffer[i] ^ (uint8_t)input_buffer[i]; 
		} 
		fwrite((uint8_t*)buffer2, sizeof(uint8_t), bytes_read, fd_out);	
		bytes_read = fread((uint8_t*)buffer, sizeof(uint8_t), 8, fd_in);
	}
	fclose(fd_out);
	fclose(fd_in);
	free(input_buffer);
	return Py_None;
}

/*----------------------------------------------------------------------------*/
static PyObject* xtea2_encipher(PyObject *self, PyObject *args) {
	char *newdata;
	const char *key;
	int n = 0;
	long counter = 0, len = 0;
	char buffer[8];
	PyObject *resultString;
	PyObject *stringObject;

	if (!PyArg_ParseTuple(args, "Osi", &stringObject, &key, &n)) {
		return NULL;
	}
	if (!PyString_Check(stringObject)) {
		return NULL;	
	}

	len = (long)PyString_Size(stringObject);
	newdata = malloc(len);
	if (newdata == NULL) return NULL;

	memcpy(newdata, PyString_AsString(stringObject), len);

	for (counter=0; counter < len; counter+=8) {
		memcpy(buffer, newdata + counter, 8);
		encipher((uint32_t)n, (uint32_t*)buffer, (uint32_t*)key);
		memcpy(newdata + counter, buffer, 8);
	}

	resultString = PyString_FromStringAndSize(newdata, len);
	free(newdata);
	return resultString;
}

/*----------------------------------------------------------------------------*/
static PyObject* xtea2_decipher(PyObject *self, PyObject *args) {
	char *newdata;
	const char *key;
	int n = 0;
	long counter = 0, len = 0;
	char buffer[8];
	PyObject *resultString;
	PyObject *stringObject;

	if (!PyArg_ParseTuple(args, "Osi", &stringObject, &key, &n)) {
		return NULL;
	}
	if (!PyString_Check(stringObject)) {
		return NULL;	
	}

	len = (long)PyString_Size(stringObject);
	newdata = malloc(len);
	if (newdata == NULL) return NULL;
	memcpy(newdata, PyString_AsString(stringObject), len);

	for (counter=0; counter < len; counter+=8) {
		memcpy(buffer, newdata + counter, 8);
		decipher((uint32_t)n, (uint32_t*)buffer, (uint32_t*)key);
		memcpy(newdata + counter, buffer, 8);
	}
	resultString = PyString_FromStringAndSize(newdata, len);
	free(newdata);
	return resultString;
}

/*----------------------------------------------------------------------------*/
static void encipher(uint32_t num_rounds, uint32_t* v, uint32_t* k) {
	uint32_t v0=v[0], v1=v[1], i;
	uint32_t sum=0, delta=0x9E3779B9; 
	for(i=0; i<num_rounds; i++) {
		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
		sum += delta;
		v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
	}
	v[0]=v0; v[1]=v1;
}
/*----------------------------------------------------------------------------*/
static void encipher2(uint32_t num_rounds, uint32_t* v, uint32_t* k) {
	uint32_t v0=v[0], v1=v[1], i;
	uint32_t sum=0, delta=0x9E3779B9, mask=0xFFFFFFFF;
	for(i=0; i<num_rounds; i++) {
		v0 = (v0+((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]))) & mask;
		sum = (sum + delta) & mask;
		v1 = (v1+((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]))) & mask;
	}
	v[0]=v0; v[1]=v1;
}

 
/*----------------------------------------------------------------------------*/
static void decipher(uint32_t num_rounds, uint32_t* v, uint32_t* k) {
	uint32_t v0=v[0], v1=v[1], i;
	uint32_t delta=0x9E3779B9, sum=delta*num_rounds;
	for(i=0; i<num_rounds; i++) {
		v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
		sum -= delta;
		v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
	}
	v[0]=v0; v[1]=v1;
}
/*----------------------------------------------------------------------------*/
static void decipher2(uint32_t num_rounds, uint32_t* v, uint32_t* k) {
	uint32_t v0=v[0], v1=v[1], i;
	uint32_t delta=0x9E3779B9, sum=delta*num_rounds, mask=0xFFFFFFFF;;
	for(i=0; i<num_rounds; i++) {
		v1 = (v1-((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]))) & mask;
		sum = (sum - delta) & mask;
		v0 = (v0-((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]))) & mask;
	}
	v[0]=v0; v[1]=v1;
}

