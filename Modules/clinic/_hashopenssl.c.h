/*[clinic input]
preserve
[clinic start generated code]*/

#if (OPENSSL_VERSION_NUMBER > 0x10100000L && !defined(OPENSSL_NO_SCRYPT) && !defined(LIBRESSL_VERSION_NUMBER))

PyDoc_STRVAR(_hashlib_scrypt__doc__,
"scrypt($module, /, password, *, salt=None, n=None, r=None, p=None,\n"
"       maxmem=0, dklen=64)\n"
"--\n"
"\n"
"scrypt password-based key derivation function.");

#define _HASHLIB_SCRYPT_METHODDEF    \
    {"scrypt", (PyCFunction)_hashlib_scrypt, METH_FASTCALL, _hashlib_scrypt__doc__},

static PyObject *
_hashlib_scrypt_impl(PyObject *module, Py_buffer *password, Py_buffer *salt,
                     PyObject *n_obj, PyObject *r_obj, PyObject *p_obj,
                     long maxmem, long dklen);

static PyObject *
_hashlib_scrypt(PyObject *module, PyObject **args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    static const char * const _keywords[] = {"password", "salt", "n", "r", "p", "maxmem", "dklen", NULL};
    static _PyArg_Parser _parser = {"y*|$y*O!O!O!ll:scrypt", _keywords, 0};
    Py_buffer password = {NULL, NULL};
    Py_buffer salt = {NULL, NULL};
    PyObject *n_obj = Py_None;
    PyObject *r_obj = Py_None;
    PyObject *p_obj = Py_None;
    long maxmem = 0;
    long dklen = 64;

    if (!_PyArg_ParseStack(args, nargs, kwnames, &_parser,
        &password, &salt, &PyLong_Type, &n_obj, &PyLong_Type, &r_obj, &PyLong_Type, &p_obj, &maxmem, &dklen)) {
        goto exit;
    }
    return_value = _hashlib_scrypt_impl(module, &password, &salt, n_obj, r_obj, p_obj, maxmem, dklen);

exit:
    /* Cleanup for password */
    if (password.obj) {
       PyBuffer_Release(&password);
    }
    /* Cleanup for salt */
    if (salt.obj) {
       PyBuffer_Release(&salt);
    }

    return return_value;
}

#endif /* (OPENSSL_VERSION_NUMBER > 0x10100000L && !defined(OPENSSL_NO_SCRYPT) && !defined(LIBRESSL_VERSION_NUMBER)) */

#ifndef _HASHLIB_SCRYPT_METHODDEF
    #define _HASHLIB_SCRYPT_METHODDEF
#endif /* !defined(_HASHLIB_SCRYPT_METHODDEF) */
/*[clinic end generated code: output=118cd7036fa0fb52 input=a9049054013a1b77]*/

PyDoc_STRVAR(_hashlib_hmac_digest__doc__,
"hmac_digest($module, /, key, msg, digest)\n"
"--\n"
"\n"
"Single-shot HMAC.");

#define _HASHLIB_HMAC_DIGEST_METHODDEF    \
    {"hmac_digest", (PyCFunction)(void(*)(void))_hashlib_hmac_digest, METH_FASTCALL|METH_KEYWORDS, _hashlib_hmac_digest__doc__},

static PyObject *
_hashlib_hmac_digest_impl(PyObject *module, Py_buffer *key, Py_buffer *msg,
                          const char *digest);

static PyObject *
_hashlib_hmac_digest(PyObject *module, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *return_value = NULL;
    static const char * const _keywords[] = {"key", "msg", "digest", NULL};
    static _PyArg_Parser _parser = {NULL, _keywords, "hmac_digest", 0};
    PyObject *argsbuf[3];
    Py_buffer key = {NULL, NULL};
    Py_buffer msg = {NULL, NULL};
    const char *digest;

    args = _PyArg_UnpackKeywords(args, nargs, NULL, kwnames, &_parser, 3, 3, 0, argsbuf);
    if (!args) {
        goto exit;
    }
    if (PyObject_GetBuffer(args[0], &key, PyBUF_SIMPLE) != 0) {
        goto exit;
    }
    if (!PyBuffer_IsContiguous(&key, 'C')) {
        _PyArg_BadArgument("hmac_digest", "argument 'key'", "contiguous buffer", args[0]);
        goto exit;
    }
    if (PyObject_GetBuffer(args[1], &msg, PyBUF_SIMPLE) != 0) {
        goto exit;
    }
    if (!PyBuffer_IsContiguous(&msg, 'C')) {
        _PyArg_BadArgument("hmac_digest", "argument 'msg'", "contiguous buffer", args[1]);
        goto exit;
    }
    if (!PyUnicode_Check(args[2])) {
        _PyArg_BadArgument("hmac_digest", "argument 'digest'", "str", args[2]);
        goto exit;
    }
    Py_ssize_t digest_length;
    digest = PyUnicode_AsUTF8AndSize(args[2], &digest_length);
    if (digest == NULL) {
        goto exit;
    }
    if (strlen(digest) != (size_t)digest_length) {
        PyErr_SetString(PyExc_ValueError, "embedded null character");
        goto exit;
    }
    return_value = _hashlib_hmac_digest_impl(module, &key, &msg, digest);

exit:
    /* Cleanup for key */
    if (key.obj) {
       PyBuffer_Release(&key);
    }
    /* Cleanup for msg */
    if (msg.obj) {
       PyBuffer_Release(&msg);
    }

    return return_value;
}

#if !defined(LIBRESSL_VERSION_NUMBER)

PyDoc_STRVAR(_hashlib_get_fips_mode__doc__,
"get_fips_mode($module, /)\n"
"--\n"
"\n"
"Determine the OpenSSL FIPS mode of operation.\n"
"\n"
"For OpenSSL 3.0.0 and newer it returns the state of the default provider\n"
"in the default OSSL context. It\'s not quite the same as FIPS_mode() but good\n"
"enough for unittests.\n"
"\n"
"Effectively any non-zero return value indicates FIPS mode;\n"
"values other than 1 may have additional significance.");

#define _HASHLIB_GET_FIPS_MODE_METHODDEF    \
    {"get_fips_mode", (PyCFunction)_hashlib_get_fips_mode, METH_NOARGS, _hashlib_get_fips_mode__doc__},

static int
_hashlib_get_fips_mode_impl(PyObject *module);

static PyObject *
_hashlib_get_fips_mode(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    PyObject *return_value = NULL;
    int _return_value;

    _return_value = _hashlib_get_fips_mode_impl(module);
    if ((_return_value == -1) && PyErr_Occurred()) {
        goto exit;
    }
    return_value = PyLong_FromLong((long)_return_value);

exit:
    return return_value;
}

#endif /* !defined(LIBRESSL_VERSION_NUMBER) */

#ifndef _HASHLIB_SCRYPT_METHODDEF
    #define _HASHLIB_SCRYPT_METHODDEF
#endif /* !defined(_HASHLIB_SCRYPT_METHODDEF) */

#ifndef _HASHLIB_GET_FIPS_MODE_METHODDEF
    #define _HASHLIB_GET_FIPS_MODE_METHODDEF
#endif /* !defined(_HASHLIB_GET_FIPS_MODE_METHODDEF) */
/*[clinic end generated code: output=4babbd88389a196b input=a9049054013a1b77]*/
