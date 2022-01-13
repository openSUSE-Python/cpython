/* Module that wraps all OpenSSL hash algorithms */

/*
 * Copyright (C) 2005-2010   Gregory P. Smith (greg@krypto.org)
 * Licensed to PSF under a Contributor Agreement.
 *
 * Derived from a skeleton of shamodule.c containing work performed by:
 *
 * Andrew Kuchling (amk@amk.ca)
 * Greg Stein (gstein@lyra.org)
 *
 */

/* Don't warn about deprecated functions, */
#ifndef OPENSSL_API_COMPAT
  // 0x10101000L == 1.1.1, 30000 == 3.0.0
  #define OPENSSL_API_COMPAT 0x10101000L
#endif
#define OPENSSL_NO_DEPRECATED 1

#ifndef Py_BUILD_CORE_BUILTIN
#  define Py_BUILD_CORE_MODULE 1
#endif

#define PY_SSIZE_T_CLEAN

#include "Python.h"
#include "hashtable.h"
#include "hashlib.h"
#include "pystrhex.h"


/* EVP is the preferred interface to hashing in OpenSSL */
#include <openssl/evp.h>
/* We use the object interface to discover what hashes OpenSSL supports. */
#include <openssl/objects.h>
#include "openssl/err.h"

#include "clinic/_hashopenssl.c.h"
/*[clinic input]
module _hashlib
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=c2b4ff081bac4be1]*/

#define MUNCH_SIZE INT_MAX

#ifndef HASH_OBJ_CONSTRUCTOR
#define HASH_OBJ_CONSTRUCTOR 0
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
/* OpenSSL < 1.1.0 */
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#define HAS_FAST_PKCS5_PBKDF2_HMAC 0
#include <openssl/hmac.h>
#else
/* OpenSSL >= 1.1.0 */
#define HAS_FAST_PKCS5_PBKDF2_HMAC 1
#endif

#define MUNCH_SIZE INT_MAX

#ifdef NID_sha3_224
#define PY_OPENSSL_HAS_SHA3 1
#endif

#if defined(EVP_MD_FLAG_XOF) && defined(NID_shake128)
#define PY_OPENSSL_HAS_SHAKE 1
#endif

#if defined(NID_blake2b512) && !defined(OPENSSL_NO_BLAKE2)
#define PY_OPENSSL_HAS_BLAKE2 1
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define PY_EVP_MD EVP_MD
#define PY_EVP_MD_fetch(algorithm, properties) EVP_MD_fetch(NULL, algorithm, properties)
#define PY_EVP_MD_up_ref(md) EVP_MD_up_ref(md)
#define PY_EVP_MD_free(md) EVP_MD_free(md)
#else
#define PY_EVP_MD const EVP_MD
#define PY_EVP_MD_fetch(algorithm, properties) EVP_get_digestbyname(algorithm)
#define PY_EVP_MD_up_ref(md) do {} while(0)
#define PY_EVP_MD_free(md) do {} while(0)
#endif

/* hash alias map and fast lookup
 *
 * Map between Python's preferred names and OpenSSL internal names. Maintain
 * cache of fetched EVP MD objects. The EVP_get_digestbyname() and
 * EVP_MD_fetch() API calls have a performance impact.
 *
 * The py_hashentry_t items are stored in a _Py_hashtable_t with py_name and
 * py_alias as keys.
 */

enum Py_hash_type {
    Py_ht_evp,            // usedforsecurity=True / default
    Py_ht_evp_nosecurity, // usedforsecurity=False
    Py_ht_mac,            // HMAC
    Py_ht_pbkdf2,         // PKBDF2
};

typedef struct {
    const char *py_name;
    const char *py_alias;
    const char *ossl_name;
    int ossl_nid;
    int refcnt;
    PY_EVP_MD *evp;
    PY_EVP_MD *evp_nosecurity;
} py_hashentry_t;

#define Py_hash_md5 "md5"
#define Py_hash_sha1 "sha1"
#define Py_hash_sha224 "sha224"
#define Py_hash_sha256 "sha256"
#define Py_hash_sha384 "sha384"
#define Py_hash_sha512 "sha512"
#define Py_hash_sha512_224 "sha512_224"
#define Py_hash_sha512_256 "sha512_256"
#define Py_hash_sha3_224 "sha3_224"
#define Py_hash_sha3_256 "sha3_256"
#define Py_hash_sha3_384 "sha3_384"
#define Py_hash_sha3_512 "sha3_512"
#define Py_hash_shake_128 "shake_128"
#define Py_hash_shake_256 "shake_256"
#define Py_hash_blake2s "blake2s"
#define Py_hash_blake2b "blake2b"

#define PY_HASH_ENTRY(py_name, py_alias, ossl_name, ossl_nid) \
    {py_name, py_alias, ossl_name, ossl_nid, 0, NULL, NULL}

static const py_hashentry_t py_hashes[] = {
    /* md5 */
    PY_HASH_ENTRY(Py_hash_md5, "MD5", SN_md5, NID_md5),
    /* sha1 */
    PY_HASH_ENTRY(Py_hash_sha1, "SHA1", SN_sha1, NID_sha1),
    /* sha2 family */
    PY_HASH_ENTRY(Py_hash_sha224, "SHA224", SN_sha224, NID_sha224),
    PY_HASH_ENTRY(Py_hash_sha256, "SHA256", SN_sha256, NID_sha256),
    PY_HASH_ENTRY(Py_hash_sha384, "SHA384", SN_sha384, NID_sha384),
    PY_HASH_ENTRY(Py_hash_sha512, "SHA512", SN_sha512, NID_sha512),
    /* truncated sha2 */
#ifdef NID_sha512_224
    PY_HASH_ENTRY(Py_hash_sha512_224, "SHA512_224", SN_sha512_224, NID_sha512_224),
    PY_HASH_ENTRY(Py_hash_sha512_256, "SHA512_256", SN_sha512_256, NID_sha512_256),
#endif
    /* sha3 */
#ifdef PY_OPENSSL_HAS_SHA3
    PY_HASH_ENTRY(Py_hash_sha3_224, NULL, SN_sha3_224, NID_sha3_224),
    PY_HASH_ENTRY(Py_hash_sha3_256, NULL, SN_sha3_256, NID_sha3_256),
    PY_HASH_ENTRY(Py_hash_sha3_384, NULL, SN_sha3_384, NID_sha3_384),
    PY_HASH_ENTRY(Py_hash_sha3_512, NULL, SN_sha3_512, NID_sha3_512),
#endif
    /* sha3 shake */
#ifdef PY_OPENSSL_HAS_SHAKE
    PY_HASH_ENTRY(Py_hash_shake_128, NULL, SN_shake128, NID_shake128),
    PY_HASH_ENTRY(Py_hash_shake_256, NULL, SN_shake256, NID_shake256),
#endif
    /* blake2 digest */
#ifdef PY_OPENSSL_HAS_BLAKE2
    PY_HASH_ENTRY(Py_hash_blake2s, "blake2s256", SN_blake2s256, NID_blake2s256),
    PY_HASH_ENTRY(Py_hash_blake2b, "blake2b512", SN_blake2b512, NID_blake2b512),
#endif
    PY_HASH_ENTRY(NULL, NULL, NULL, 0),
};

static Py_uhash_t
py_hashentry_t_hash_name(const void *key) {
    return _Py_HashBytes(key, strlen((const char *)key));
}

static int
py_hashentry_t_compare_name(const void *key1, const void *key2) {
    return strcmp((const char *)key1, (const char *)key2) == 0;
}

static void
py_hashentry_t_destroy_value(void *entry) {
    py_hashentry_t *h = (py_hashentry_t *)entry;
    if (--(h->refcnt) == 0) {
        if (h->evp != NULL) {
            PY_EVP_MD_free(h->evp);
            h->evp = NULL;
        }
        if (h->evp_nosecurity != NULL) {
            PY_EVP_MD_free(h->evp_nosecurity);
            h->evp_nosecurity = NULL;
        }
        PyMem_Free(entry);
    }
}

static _Py_hashtable_t *
py_hashentry_table_new(void) {
    _Py_hashtable_t *ht = _Py_hashtable_new_full(
        py_hashentry_t_hash_name,
        py_hashentry_t_compare_name,
        NULL,
        py_hashentry_t_destroy_value,
        NULL
    );
    if (ht == NULL) {
        return NULL;
    }

    for (const py_hashentry_t *h = py_hashes; h->py_name != NULL; h++) {
        py_hashentry_t *entry = (py_hashentry_t *)PyMem_Malloc(sizeof(py_hashentry_t));
        if (entry == NULL) {
            goto error;
        }
        memcpy(entry, h, sizeof(py_hashentry_t));

        if (_Py_hashtable_set(ht, (const void*)entry->py_name, (void*)entry) < 0) {
            PyMem_Free(entry);
            goto error;
        }
        entry->refcnt = 1;

        if (h->py_alias != NULL) {
            if (_Py_hashtable_set(ht, (const void*)entry->py_alias, (void*)entry) < 0) {
                PyMem_Free(entry);
                goto error;
            }
            entry->refcnt++;
        }
    }

    return ht;
  error:
    _Py_hashtable_destroy(ht);
    return NULL;
}

/* Module state */
static PyModuleDef _hashlibmodule;

typedef struct {
    PyTypeObject *EVPtype;
    PyTypeObject *HMACtype;
#ifdef PY_OPENSSL_HAS_SHAKE
    PyTypeObject *EVPXOFtype;
#endif
    _Py_hashtable_t *hashtable;
} _hashlibstate;

static inline _hashlibstate*
get_hashlib_state(PyObject *module)
{
    void *state = PyModule_GetState(module);
    assert(state != NULL);
    return (_hashlibstate *)state;
}

typedef struct {
    PyObject_HEAD
    PyObject            *name;  /* name of this hash algorithm */
    EVP_MD_CTX          *ctx;   /* OpenSSL message digest context */
#ifdef WITH_THREAD
    PyThread_type_lock   lock;  /* OpenSSL context lock */
#endif
} EVPobject;


static PyTypeObject EVPtype;


#define DEFINE_CONSTS_FOR_NEW(Name)  \
    static PyObject *CONST_ ## Name ## _name_obj = NULL; \
    static EVP_MD_CTX *CONST_new_ ## Name ## _ctx_p = NULL;

DEFINE_CONSTS_FOR_NEW(md5)
DEFINE_CONSTS_FOR_NEW(sha1)
DEFINE_CONSTS_FOR_NEW(sha224)
DEFINE_CONSTS_FOR_NEW(sha256)
DEFINE_CONSTS_FOR_NEW(sha384)
DEFINE_CONSTS_FOR_NEW(sha512)


/* LCOV_EXCL_START */
static PyObject *
_setException(PyObject *exc, const char* altmsg, ...)
{
    unsigned long errcode = ERR_peek_last_error();
    const char *lib, *func, *reason;
    va_list vargs;

#ifdef HAVE_STDARG_PROTOTYPES
    va_start(vargs, altmsg);
#else
    va_start(vargs);
#endif
    if (!errcode) {
        if (altmsg == NULL) {
            PyErr_SetString(exc, "no reason supplied");
        } else {
            PyErr_FormatV(exc, altmsg, vargs);
        }
        va_end(vargs);
        return NULL;
    }
    va_end(vargs);
    ERR_clear_error();

    lib = ERR_lib_error_string(errcode);
    func = ERR_func_error_string(errcode);
    reason = ERR_reason_error_string(errcode);

    if (lib && func) {
        PyErr_Format(exc, "[%s: %s] %s", lib, func, reason);
    }
    else if (lib) {
        PyErr_Format(exc, "[%s] %s", lib, reason);
    }
    else {
        PyErr_SetString(exc, reason);
    }
    return NULL;
}
/* LCOV_EXCL_STOP */

/* {Py_tp_new, NULL} doesn't block __new__ */
static PyObject *
_disabled_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    PyErr_Format(PyExc_TypeError,
        "cannot create '%.100s' instances", _PyType_Name(type));
    return NULL;
}

static PyObject*
py_digest_name(const EVP_MD *md)
{
    int nid = EVP_MD_nid(md);
    const char *name = NULL;
    const py_hashentry_t *h;

    for (h = py_hashes; h->py_name != NULL; h++) {
        if (h->ossl_nid == nid) {
            name = h->py_name;
            break;
        }
    }
    if (name == NULL) {
        /* Ignore aliased names and only use long, lowercase name. The aliases
         * pollute the list and OpenSSL appears to have its own definition of
         * alias as the resulting list still contains duplicate and alternate
         * names for several algorithms.
         */
        name = OBJ_nid2ln(nid);
        if (name == NULL)
            name = OBJ_nid2sn(nid);
    }

    return PyUnicode_FromString(name);
}

/* Get EVP_MD by HID and purpose */
static PY_EVP_MD*
py_digest_by_name(PyObject *module, const char *name, enum Py_hash_type py_ht)
{
    PY_EVP_MD *digest = NULL;
    _hashlibstate *state = get_hashlib_state(module);
    py_hashentry_t *entry = (py_hashentry_t *)_Py_hashtable_get(
        state->hashtable, (const void*)name
    );

    if (entry != NULL) {
        switch (py_ht) {
        case Py_ht_evp:
        case Py_ht_mac:
        case Py_ht_pbkdf2:
            if (entry->evp == NULL) {
                entry->evp = PY_EVP_MD_fetch(entry->ossl_name, NULL);
            }
            digest = entry->evp;
            break;
        case Py_ht_evp_nosecurity:
            if (entry->evp_nosecurity == NULL) {
                entry->evp_nosecurity = PY_EVP_MD_fetch(entry->ossl_name, "-fips");
            }
            digest = entry->evp_nosecurity;
            break;
        }
        if (digest != NULL) {
            PY_EVP_MD_up_ref(digest);
        }
    } else {
        // Fall back for looking up an unindexed OpenSSL specific name.
        switch (py_ht) {
        case Py_ht_evp:
        case Py_ht_mac:
        case Py_ht_pbkdf2:
            digest = PY_EVP_MD_fetch(name, NULL);
            break;
        case Py_ht_evp_nosecurity:
            digest = PY_EVP_MD_fetch(name, "-fips");
            break;
        }
    }
    if (digest == NULL) {
        _setException(PyExc_ValueError, "unsupported hash type %s", name);
        return NULL;
    }
    return digest;
}

static EVPobject *
newEVPobject(PyObject *name)
{
    EVPobject *retval = (EVPobject *)PyObject_New(EVPobject, &EVPtype);
    if (retval == NULL) {
        return NULL;
    }

    retval->ctx = EVP_MD_CTX_new();
    if (retval->ctx == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    /* save the name for .name to return */
    Py_INCREF(name);
    retval->name = name;
#ifdef WITH_THREAD
    retval->lock = NULL;
#endif

    return retval;
}

static void
EVP_hash(EVPobject *self, const void *vp, Py_ssize_t len)
{
    unsigned int process;
    const unsigned char *cp = (const unsigned char *)vp;
    while (0 < len) {
        if (len > (Py_ssize_t)MUNCH_SIZE)
            process = MUNCH_SIZE;
        else
            process = Py_SAFE_DOWNCAST(len, Py_ssize_t, unsigned int);
        if (!EVP_DigestUpdate(self->ctx, (const void*)cp, process)) {
            _setException(PyExc_ValueError, NULL);
            return -1;
        }
        len -= process;
        cp += process;
    }
}

/* Internal methods for a hash object */

static void
EVP_dealloc(EVPobject *self)
{
#ifdef WITH_THREAD
    if (self->lock != NULL)
        PyThread_free_lock(self->lock);
#endif
    EVP_MD_CTX_free(self->ctx);
    Py_XDECREF(self->name);
    PyObject_Del(self);
}

static int
locked_EVP_MD_CTX_copy(EVP_MD_CTX *new_ctx_p, EVPobject *self)
{
    int result;
    ENTER_HASHLIB(self);
    result = EVP_MD_CTX_copy(new_ctx_p, self->ctx);
    LEAVE_HASHLIB(self);
    return result;
}

/* External methods for a hash object */

PyDoc_STRVAR(EVP_copy__doc__, "Return a copy of the hash object.");


static PyObject *
EVP_copy(EVPobject *self, PyObject *unused)
{
    EVPobject *newobj;

    if ( (newobj = newEVPobject(self->name))==NULL)
        return NULL;

    if (!locked_EVP_MD_CTX_copy(newobj->ctx, self)) {
        Py_DECREF(newobj);
        return _setException(PyExc_ValueError, NULL);
    }
    return (PyObject *)newobj;
}

PyDoc_STRVAR(EVP_digest__doc__,
"Return the digest value as a bytes object.");

static PyObject *
EVP_digest(EVPobject *self, PyObject *unused)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *temp_ctx;
    PyObject *retval;
    unsigned int digest_size;

    temp_ctx = EVP_MD_CTX_new();
    if (temp_ctx == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    if (!locked_EVP_MD_CTX_copy(temp_ctx, self)) {
        return _setException(PyExc_ValueError, NULL);
    }
    digest_size = EVP_MD_CTX_size(temp_ctx);
    if (!EVP_DigestFinal(temp_ctx, digest, NULL)) {
        _setException(PyExc_ValueError, NULL);
        return NULL;
    }

    retval = PyBytes_FromStringAndSize((const char *)digest, digest_size);
    EVP_MD_CTX_free(temp_ctx);
    return retval;
}

PyDoc_STRVAR(EVP_hexdigest__doc__,
"Return the digest value as a string of hexadecimal digits.");

static PyObject *
EVP_hexdigest(EVPobject *self, PyObject *unused)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *temp_ctx;
    unsigned int digest_size;

    temp_ctx = EVP_MD_CTX_new();
    if (temp_ctx == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    /* Get the raw (binary) digest value */
    if (!locked_EVP_MD_CTX_copy(temp_ctx, self)) {
        return _setException(PyExc_ValueError, NULL);
    }
    digest_size = EVP_MD_CTX_size(temp_ctx);
    if (!EVP_DigestFinal(temp_ctx, digest, NULL)) {
        _setException(PyExc_ValueError, NULL);
        return NULL;
    }

    EVP_MD_CTX_free(temp_ctx);

    return _Py_strhex((const char *)digest, digest_size);
}

PyDoc_STRVAR(EVP_update__doc__,
"Update this hash object's state with the provided string.");

static PyObject *
EVP_update(EVPobject *self, PyObject *args)
{
    PyObject *obj;
    Py_buffer view;

    if (!PyArg_ParseTuple(args, "O:update", &obj))
        return NULL;

    GET_BUFFER_VIEW_OR_ERROUT(obj, &view);

#ifdef WITH_THREAD
    if (self->lock == NULL && view.len >= HASHLIB_GIL_MINSIZE) {
        self->lock = PyThread_allocate_lock();
        /* fail? lock = NULL and we fail over to non-threaded code. */
    }

    if (self->lock != NULL) {
        Py_BEGIN_ALLOW_THREADS
        PyThread_acquire_lock(self->lock, 1);
        EVP_hash(self, view.buf, view.len);
        PyThread_release_lock(self->lock);
        Py_END_ALLOW_THREADS
    } else {
        EVP_hash(self, view.buf, view.len);
    }
#else
    EVP_hash(self, view.buf, view.len);
#endif

    PyBuffer_Release(&view);
    Py_RETURN_NONE;
}

static PyMethodDef EVP_methods[] = {
    {"update",    (PyCFunction)EVP_update,    METH_VARARGS, EVP_update__doc__},
    {"digest",    (PyCFunction)EVP_digest,    METH_NOARGS,  EVP_digest__doc__},
    {"hexdigest", (PyCFunction)EVP_hexdigest, METH_NOARGS,  EVP_hexdigest__doc__},
    {"copy",      (PyCFunction)EVP_copy,      METH_NOARGS,  EVP_copy__doc__},
    {NULL, NULL}  /* sentinel */
};

static PyObject *
EVP_get_block_size(EVPobject *self, void *closure)
{
    long block_size;
    block_size = EVP_MD_CTX_block_size(self->ctx);
    return PyLong_FromLong(block_size);
}

static PyObject *
EVP_get_digest_size(EVPobject *self, void *closure)
{
    long size;
    size = EVP_MD_CTX_size(self->ctx);
    return PyLong_FromLong(size);
}

static PyMemberDef EVP_members[] = {
    {"name", T_OBJECT, offsetof(EVPobject, name), READONLY, PyDoc_STR("algorithm name.")},
    {NULL}  /* Sentinel */
};

static PyGetSetDef EVP_getseters[] = {
    {"digest_size",
     (getter)EVP_get_digest_size, NULL,
     NULL,
     NULL},
    {"block_size",
     (getter)EVP_get_block_size, NULL,
     NULL,
     NULL},
    {NULL}  /* Sentinel */
};


static PyObject *
EVP_repr(EVPobject *self)
{
    return PyUnicode_FromFormat("<%U HASH object @ %p>", self->name, self);
}

#if HASH_OBJ_CONSTRUCTOR
static int
EVP_tp_init(EVPobject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"name", "string", NULL};
    PyObject *name_obj = NULL;
    PyObject *data_obj = NULL;
    Py_buffer view;
    char *nameStr;
    const EVP_MD *digest;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|O:HASH", kwlist,
                                     &name_obj, &data_obj)) {
        return -1;
    }

    if (data_obj)
        GET_BUFFER_VIEW_OR_ERROUT(data_obj, &view);

    if (!PyArg_Parse(name_obj, "s", &nameStr)) {
        PyErr_SetString(PyExc_TypeError, "name must be a string");
        if (data_obj)
            PyBuffer_Release(&view);
        return -1;
    }

    digest = EVP_get_digestbyname(nameStr);
    if (!digest) {
        PyErr_SetString(PyExc_ValueError, "unknown hash function");
        if (data_obj)
            PyBuffer_Release(&view);
        return -1;
    }
    if (!EVP_DigestInit(self->ctx, digest)) {
        _setException(PyExc_ValueError);
        if (data_obj)
            PyBuffer_Release(&view);
        return -1;
    }

    Py_INCREF(name_obj);
    Py_XSETREF(self->name, name_obj);

    if (data_obj) {
        if (view.len >= HASHLIB_GIL_MINSIZE) {
            Py_BEGIN_ALLOW_THREADS
            EVP_hash(self, view.buf, view.len);
            Py_END_ALLOW_THREADS
        } else {
            EVP_hash(self, view.buf, view.len);
        }
        PyBuffer_Release(&view);
    }

    return 0;
}
#endif


PyDoc_STRVAR(hashtype_doc,
"A hash represents the object used to calculate a checksum of a\n\
string of information.\n\
\n\
Methods:\n\
\n\
update() -- updates the current digest with an additional string\n\
digest() -- return the current digest value\n\
hexdigest() -- return the current digest as a string of hexadecimal digits\n\
copy() -- return a copy of the current hash object\n\
\n\
Attributes:\n\
\n\
name -- the hash algorithm being used by this object\n\
digest_size -- number of bytes in this hashes output\n");

static PyTypeObject EVPtype = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_hashlib.HASH",    /*tp_name*/
    sizeof(EVPobject),  /*tp_basicsize*/
    0,                  /*tp_itemsize*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    EVPtype_slots
};

#ifdef PY_OPENSSL_HAS_SHAKE

/*[clinic input]
_hashlib.HASHXOF.digest as EVPXOF_digest

  length: Py_ssize_t

Return the digest value as a bytes object.
[clinic start generated code]*/

static PyObject *
EVPXOF_digest_impl(EVPobject *self, Py_ssize_t length)
/*[clinic end generated code: output=ef9320c23280efad input=816a6537cea3d1db]*/
{
    EVP_MD_CTX *temp_ctx;
    PyObject *retval = PyBytes_FromStringAndSize(NULL, length);

    if (retval == NULL) {
        return NULL;
    }

    temp_ctx = EVP_MD_CTX_new();
    if (temp_ctx == NULL) {
        Py_DECREF(retval);
        PyErr_NoMemory();
        return NULL;
    }

    if (!locked_EVP_MD_CTX_copy(temp_ctx, self)) {
        Py_DECREF(retval);
        EVP_MD_CTX_free(temp_ctx);
        return _setException(PyExc_ValueError, NULL);
    }
    if (!EVP_DigestFinalXOF(temp_ctx,
                            (unsigned char*)PyBytes_AS_STRING(retval),
                            length)) {
        Py_DECREF(retval);
        EVP_MD_CTX_free(temp_ctx);
        _setException(PyExc_ValueError, NULL);
        return NULL;
    }

    EVP_MD_CTX_free(temp_ctx);
    return retval;
}

/*[clinic input]
_hashlib.HASHXOF.hexdigest as EVPXOF_hexdigest

    length: Py_ssize_t

Return the digest value as a string of hexadecimal digits.
[clinic start generated code]*/

static PyObject *
EVPXOF_hexdigest_impl(EVPobject *self, Py_ssize_t length)
/*[clinic end generated code: output=eb3e6ee7788bf5b2 input=5f9d6a8f269e34df]*/
{
    unsigned char *digest;
    EVP_MD_CTX *temp_ctx;
    PyObject *retval;

    digest = (unsigned char*)PyMem_Malloc(length);
    if (digest == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    temp_ctx = EVP_MD_CTX_new();
    if (temp_ctx == NULL) {
        PyMem_Free(digest);
        PyErr_NoMemory();
        return NULL;
    }

    /* Get the raw (binary) digest value */
    if (!locked_EVP_MD_CTX_copy(temp_ctx, self)) {
        PyMem_Free(digest);
        EVP_MD_CTX_free(temp_ctx);
        return _setException(PyExc_ValueError, NULL);
    }
    if (!EVP_DigestFinalXOF(temp_ctx, digest, length)) {
        PyMem_Free(digest);
        EVP_MD_CTX_free(temp_ctx);
        _setException(PyExc_ValueError, NULL);
        return NULL;
    }

    EVP_MD_CTX_free(temp_ctx);

    retval = _Py_strhex((const char *)digest, length);
    PyMem_Free(digest);
    return retval;
}

static PyMethodDef EVPXOF_methods[] = {
    EVPXOF_DIGEST_METHODDEF
    EVPXOF_HEXDIGEST_METHODDEF
    {NULL, NULL}  /* sentinel */
};


static PyObject *
EVPXOF_get_digest_size(EVPobject *self, void *closure)
{
    return PyLong_FromLong(0);
}

static PyGetSetDef EVPXOF_getseters[] = {
    {"digest_size",
     (getter)EVPXOF_get_digest_size, NULL,
     NULL,
     NULL},
    {NULL}  /* Sentinel */
};

PyDoc_STRVAR(hashxoftype_doc,
"HASHXOF(name, string=b\'\')\n"
"--\n"
"\n"
"A hash is an object used to calculate a checksum of a string of information.\n"
"\n"
"Methods:\n"
"\n"
"update() -- updates the current digest with an additional string\n"
"digest(length) -- return the current digest value\n"
"hexdigest(length) -- return the current digest as a string of hexadecimal digits\n"
"copy() -- return a copy of the current hash object\n"
"\n"
"Attributes:\n"
"\n"
"name -- the hash algorithm being used by this object\n"
"digest_size -- number of bytes in this hashes output");

static PyType_Slot EVPXOFtype_slots[] = {
    {Py_tp_doc, (char *)hashxoftype_doc},
    {Py_tp_methods, EVPXOF_methods},
    {Py_tp_getset, EVPXOF_getseters},
    {Py_tp_new, _disabled_new},
    {0, 0},
};

static PyType_Spec EVPXOFtype_spec = {
    "_hashlib.HASHXOF",    /*tp_name*/
    sizeof(EVPobject),  /*tp_basicsize*/
    0,                  /*tp_itemsize*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    EVPXOFtype_slots
};


#endif
#if HASH_OBJ_CONSTRUCTOR
    (initproc)EVP_tp_init, /* tp_init */
#endif
};

static PyObject*
py_evp_fromname(PyObject *module, const char *digestname, PyObject *data_obj,
                int usedforsecurity)
{
    Py_buffer view = { 0 };
    PY_EVP_MD *digest = NULL;
    PyTypeObject *type;
    EVPobject *self = NULL;

    if (data_obj != NULL) {
        GET_BUFFER_VIEW_OR_ERROUT(data_obj, &view);
    }

    digest = py_digest_by_name(
        module, digestname, usedforsecurity ? Py_ht_evp : Py_ht_evp_nosecurity
    );
    if (digest == NULL) {
        goto exit;
    }

#ifdef PY_OPENSSL_HAS_SHAKE
    if ((EVP_MD_flags(digest) & EVP_MD_FLAG_XOF) == EVP_MD_FLAG_XOF) {
        type = get_hashlib_state(module)->EVPXOFtype;
    } else
#endif
    {
        type = get_hashlib_state(module)->EVPtype;
    }

    self = newEVPobject(type);
    if (self == NULL) {
        goto exit;
    }

#if defined(EVP_MD_CTX_FLAG_NON_FIPS_ALLOW) && OPENSSL_VERSION_NUMBER < 0x30000000L
    // In OpenSSL 1.1.1 the non FIPS allowed flag is context specific while
    // in 3.0.0 it is a different EVP_MD provider.
    if (!usedforsecurity) {
        EVP_MD_CTX_set_flags(self->ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    }
#endif

    int result = EVP_DigestInit_ex(self->ctx, digest, NULL);
    if (!result) {
        _setException(PyExc_ValueError, NULL);
        Py_CLEAR(self);
        goto exit;
    }

    if (view.buf && view.len) {
        if (view.len >= HASHLIB_GIL_MINSIZE) {
            Py_BEGIN_ALLOW_THREADS
            result = EVP_hash(self, view.buf, view.len);
            Py_END_ALLOW_THREADS
        } else {
            result = EVP_hash(self, view.buf, view.len);
        }
        if (result == -1) {
            Py_CLEAR(self);
            goto exit;
        }
    }

  exit:
    if (data_obj != NULL) {
        PyBuffer_Release(&view);
    }
    if (digest != NULL) {
        PY_EVP_MD_free(digest);
    }

    return (PyObject *)self;
}


/* The module-level function: new() */

PyDoc_STRVAR(EVP_new__doc__,
"Return a new hash object using the named algorithm.\n\
An optional string argument may be provided and will be\n\
automatically hashed.\n\
\n\
The MD5 and SHA1 algorithms are always supported.\n");

static PyObject *
EVP_new(PyObject *self, PyObject *args, PyObject *kwdict)
{
    char *name;
    if (!PyArg_Parse(name_obj, "s", &name)) {
        PyErr_SetString(PyExc_TypeError, "name must be a string");
        return NULL;
    }
    return py_evp_fromname(module, name, data_obj, usedforsecurity);
}



PyDoc_STRVAR(pbkdf2_hmac__doc__,
"pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None) -> key\n\
\n\
Password based key derivation function 2 (PKCS #5 v2.0) with HMAC as\n\
pseudorandom function.");

static PyObject *
pbkdf2_hmac(PyObject *self, PyObject *args, PyObject *kwdict)
{
    return py_evp_fromname(module, Py_hash_md5, data_obj, usedforsecurity);
}


/*[clinic input]
_hashlib.openssl_sha1

    string as data_obj: object(py_default="b''") = NULL
    *
    usedforsecurity: bool = True

Returns a sha1 hash object; optionally initialized with a string

[clinic start generated code]*/

static PyObject *
_hashlib_openssl_sha1_impl(PyObject *module, PyObject *data_obj,
                           int usedforsecurity)
/*[clinic end generated code: output=6813024cf690670d input=948f2f4b6deabc10]*/
{
    return py_evp_fromname(module, Py_hash_sha1, data_obj, usedforsecurity);
}


/*[clinic input]
_hashlib.openssl_sha224

    string as data_obj: object(py_default="b''") = NULL
    *
    usedforsecurity: bool = True

Returns a sha224 hash object; optionally initialized with a string

[clinic start generated code]*/

static PyObject *
_hashlib_openssl_sha224_impl(PyObject *module, PyObject *data_obj,
                             int usedforsecurity)
/*[clinic end generated code: output=a2dfe7cc4eb14ebb input=f9272821fadca505]*/
{
    return py_evp_fromname(module, Py_hash_sha224, data_obj, usedforsecurity);
}


/*[clinic input]
_hashlib.openssl_sha256

    string as data_obj: object(py_default="b''") = NULL
    *
    usedforsecurity: bool = True

Returns a sha256 hash object; optionally initialized with a string

[clinic start generated code]*/

static PyObject *
_hashlib_openssl_sha256_impl(PyObject *module, PyObject *data_obj,
                             int usedforsecurity)
/*[clinic end generated code: output=1f874a34870f0a68 input=549fad9d2930d4c5]*/
{
    return py_evp_fromname(module, Py_hash_sha256, data_obj, usedforsecurity);
}


/*[clinic input]
_hashlib.openssl_sha384

    string as data_obj: object(py_default="b''") = NULL
    *
    usedforsecurity: bool = True

Returns a sha384 hash object; optionally initialized with a string

[clinic start generated code]*/

static PyObject *
_hashlib_openssl_sha384_impl(PyObject *module, PyObject *data_obj,
                             int usedforsecurity)
/*[clinic end generated code: output=58529eff9ca457b2 input=48601a6e3bf14ad7]*/
{
    return py_evp_fromname(module, Py_hash_sha384, data_obj, usedforsecurity);
}


/*[clinic input]
_hashlib.openssl_sha512

    string as data_obj: object(py_default="b''") = NULL
    *
    usedforsecurity: bool = True

Returns a sha512 hash object; optionally initialized with a string

[clinic start generated code]*/

static PyObject *
_hashlib_openssl_sha512_impl(PyObject *module, PyObject *data_obj,
                             int usedforsecurity)
/*[clinic end generated code: output=2c744c9e4a40d5f6 input=c5c46a2a817aa98f]*/
{
    return py_evp_fromname(module, Py_hash_sha512, data_obj, usedforsecurity);
}


#ifdef PY_OPENSSL_HAS_SHA3

/*[clinic input]
_hashlib.openssl_sha3_224

    string as data_obj: object(py_default="b''") = NULL
    *
    usedforsecurity: bool = True

Returns a sha3-224 hash object; optionally initialized with a string

[clinic start generated code]*/

static PyObject *
_hashlib_openssl_sha3_224_impl(PyObject *module, PyObject *data_obj,
                               int usedforsecurity)
/*[clinic end generated code: output=144641c1d144b974 input=e3a01b2888916157]*/
{
    return py_evp_fromname(module, Py_hash_sha3_224, data_obj, usedforsecurity);
}

/*[clinic input]
_hashlib.openssl_sha3_256

    string as data_obj: object(py_default="b''") = NULL
    *
    usedforsecurity: bool = True

Returns a sha3-256 hash object; optionally initialized with a string

[clinic start generated code]*/

static PyObject *
_hashlib_openssl_sha3_256_impl(PyObject *module, PyObject *data_obj,
                               int usedforsecurity)
/*[clinic end generated code: output=c61f1ab772d06668 input=e2908126c1b6deed]*/
{
    return py_evp_fromname(module, Py_hash_sha3_256, data_obj , usedforsecurity);
}

/*[clinic input]
_hashlib.openssl_sha3_384

    string as data_obj: object(py_default="b''") = NULL
    *
    usedforsecurity: bool = True

Returns a sha3-384 hash object; optionally initialized with a string

[clinic start generated code]*/

static PyObject *
_hashlib_openssl_sha3_384_impl(PyObject *module, PyObject *data_obj,
                               int usedforsecurity)
/*[clinic end generated code: output=f68e4846858cf0ee input=ec0edf5c792f8252]*/
{
    return py_evp_fromname(module, Py_hash_sha3_384, data_obj , usedforsecurity);
}

/*[clinic input]
_hashlib.openssl_sha3_512

    string as data_obj: object(py_default="b''") = NULL
    *
    usedforsecurity: bool = True

Returns a sha3-512 hash object; optionally initialized with a string

[clinic start generated code]*/

static PyObject *
_hashlib_openssl_sha3_512_impl(PyObject *module, PyObject *data_obj,
                               int usedforsecurity)
/*[clinic end generated code: output=2eede478c159354a input=64e2cc0c094d56f4]*/
{
    return py_evp_fromname(module, Py_hash_sha3_512, data_obj , usedforsecurity);
}
#endif /* PY_OPENSSL_HAS_SHA3 */

#ifdef PY_OPENSSL_HAS_SHAKE
/*[clinic input]
_hashlib.openssl_shake_128

    string as data_obj: object(py_default="b''") = NULL
    *
    usedforsecurity: bool = True

Returns a shake-128 variable hash object; optionally initialized with a string

[clinic start generated code]*/

static PyObject *
_hashlib_openssl_shake_128_impl(PyObject *module, PyObject *data_obj,
                                int usedforsecurity)
/*[clinic end generated code: output=bc49cdd8ada1fa97 input=6c9d67440eb33ec8]*/
{
    return py_evp_fromname(module, Py_hash_shake_128, data_obj , usedforsecurity);
}

/*[clinic input]
_hashlib.openssl_shake_256

    string as data_obj: object(py_default="b''") = NULL
    *
    usedforsecurity: bool = True

Returns a shake-256 variable hash object; optionally initialized with a string

[clinic start generated code]*/

static PyObject *
_hashlib_openssl_shake_256_impl(PyObject *module, PyObject *data_obj,
                                int usedforsecurity)
/*[clinic end generated code: output=358d213be8852df7 input=479cbe9fefd4a9f8]*/
{
    return py_evp_fromname(module, Py_hash_shake_256, data_obj , usedforsecurity);
}
#endif /* PY_OPENSSL_HAS_SHAKE */

/*[clinic input]
_hashlib.pbkdf2_hmac as pbkdf2_hmac

    hash_name: str
    password: Py_buffer
    salt: Py_buffer
    iterations: long
    dklen as dklen_obj: object = None

Password based key derivation function 2 (PKCS #5 v2.0) with HMAC as pseudorandom function.
[clinic start generated code]*/

static PyObject *
pbkdf2_hmac_impl(PyObject *module, const char *hash_name,
                 Py_buffer *password, Py_buffer *salt, long iterations,
                 PyObject *dklen_obj)
/*[clinic end generated code: output=144b76005416599b input=ed3ab0d2d28b5d5c]*/
{
    PyObject *key_obj = NULL;
    char *key;
    long dklen;
    int retval;

    PY_EVP_MD *digest = py_digest_by_name(module, hash_name, Py_ht_pbkdf2);
    if (digest == NULL) {
        PyErr_SetString(PyExc_ValueError, "unsupported hash type");
        goto end;
    }

    if (password.len > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "password is too long.");
        goto end;
    }

    if (salt.len > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "salt is too long.");
        goto end;
    }

    if (iterations < 1) {
        PyErr_SetString(PyExc_ValueError,
                        "iteration value must be greater than 0.");
        goto end;
    }
    if (iterations > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "iteration value is too great.");
        goto end;
    }

    if (dklen_obj == Py_None) {
        dklen = EVP_MD_size(digest);
    } else {
        dklen = PyLong_AsLong(dklen_obj);
        if ((dklen == -1) && PyErr_Occurred()) {
            goto end;
        }
    }
    if (dklen < 1) {
        PyErr_SetString(PyExc_ValueError,
                        "key length must be greater than 0.");
        goto end;
    }
    if (dklen > INT_MAX) {
        /* INT_MAX is always smaller than dkLen max (2^32 - 1) * hLen */
        PyErr_SetString(PyExc_OverflowError,
                        "key length is too great.");
        goto end;
    }

    key_obj = PyBytes_FromStringAndSize(NULL, dklen);
    if (key_obj == NULL) {
        goto end;
    }
    key = PyBytes_AS_STRING(key_obj);

    Py_BEGIN_ALLOW_THREADS
#if HAS_FAST_PKCS5_PBKDF2_HMAC
    retval = PKCS5_PBKDF2_HMAC((char*)password.buf, (int)password.len,
                               (unsigned char *)salt.buf, (int)salt.len,
                               iterations, digest, dklen,
                               (unsigned char *)key);
#else
    retval = PKCS5_PBKDF2_HMAC_fast((char*)password.buf, (int)password.len,
                                    (unsigned char *)salt.buf, (int)salt.len,
                                    iterations, digest, dklen,
                                    (unsigned char *)key);
#endif
    Py_END_ALLOW_THREADS

    if (!retval) {
        Py_CLEAR(key_obj);
        _setException(PyExc_ValueError, NULL);
        goto end;
    }

  end:
    if (digest != NULL) {
        PY_EVP_MD_free(digest);
    }
    return key_obj;
}

#endif

#if OPENSSL_VERSION_NUMBER > 0x10100000L && !defined(OPENSSL_NO_SCRYPT) && !defined(LIBRESSL_VERSION_NUMBER)
#define PY_SCRYPT 1

/* XXX: Parameters salt, n, r and p should be required keyword-only parameters.
   They are optional in the Argument Clinic declaration only due to a
   limitation of PyArg_ParseTupleAndKeywords. */

/*[clinic input]
_hashlib.scrypt

    password: Py_buffer
    *
    salt: Py_buffer = None
    n as n_obj: object(subclass_of='&PyLong_Type') = None
    r as r_obj: object(subclass_of='&PyLong_Type') = None
    p as p_obj: object(subclass_of='&PyLong_Type') = None
    maxmem: long = 0
    dklen: long = 64


scrypt password-based key derivation function.
[clinic start generated code]*/

static PyObject *
_hashlib_scrypt_impl(PyObject *module, Py_buffer *password, Py_buffer *salt,
                     PyObject *n_obj, PyObject *r_obj, PyObject *p_obj,
                     long maxmem, long dklen)
/*[clinic end generated code: output=14849e2aa2b7b46c input=48a7d63bf3f75c42]*/
{
    PyObject *key_obj = NULL;
    char *key;
    int retval;
    unsigned long n, r, p;

    if (password->len > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "password is too long.");
        return NULL;
    }

    if (salt->buf == NULL) {
        PyErr_SetString(PyExc_TypeError,
                        "salt is required");
        return NULL;
    }
    if (salt->len > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "salt is too long.");
        return NULL;
    }

    n = PyLong_AsUnsignedLong(n_obj);
    if (n == (unsigned long) -1 && PyErr_Occurred()) {
        PyErr_SetString(PyExc_TypeError,
                        "n is required and must be an unsigned int");
        return NULL;
    }
    if (n < 2 || n & (n - 1)) {
        PyErr_SetString(PyExc_ValueError,
                        "n must be a power of 2.");
        return NULL;
    }

    r = PyLong_AsUnsignedLong(r_obj);
    if (r == (unsigned long) -1 && PyErr_Occurred()) {
        PyErr_SetString(PyExc_TypeError,
                         "r is required and must be an unsigned int");
        return NULL;
    }

    p = PyLong_AsUnsignedLong(p_obj);
    if (p == (unsigned long) -1 && PyErr_Occurred()) {
        PyErr_SetString(PyExc_TypeError,
                         "p is required and must be an unsigned int");
        return NULL;
    }

    if (maxmem < 0 || maxmem > INT_MAX) {
        /* OpenSSL 1.1.0 restricts maxmem to 32MB. It may change in the
           future. The maxmem constant is private to OpenSSL. */
        PyErr_Format(PyExc_ValueError,
                     "maxmem must be positive and smaller than %d",
                      INT_MAX);
        return NULL;
    }

    if (dklen < 1 || dklen > INT_MAX) {
        PyErr_Format(PyExc_ValueError,
                    "dklen must be greater than 0 and smaller than %d",
                    INT_MAX);
        return NULL;
    }

    /* let OpenSSL validate the rest */
    retval = EVP_PBE_scrypt(NULL, 0, NULL, 0, n, r, p, maxmem, NULL, 0);
    if (!retval) {
        _setException(PyExc_ValueError, "Invalid parameter combination for n, r, p, maxmem.");
        return NULL;
   }

    key_obj = PyBytes_FromStringAndSize(NULL, dklen);
    if (key_obj == NULL) {
        return NULL;
    }
    key = PyBytes_AS_STRING(key_obj);

    Py_BEGIN_ALLOW_THREADS
    retval = EVP_PBE_scrypt(
        (const char*)password->buf, (size_t)password->len,
        (const unsigned char *)salt->buf, (size_t)salt->len,
        n, r, p, maxmem,
        (unsigned char *)key, (size_t)dklen
    );
    Py_END_ALLOW_THREADS

    if (!retval) {
        Py_CLEAR(key_obj);
        _setException(PyExc_ValueError, NULL);
        return NULL;
    }
    return key_obj;
}
#endif

/* Fast HMAC for hmac.digest()
 */

/*[clinic input]
_hashlib.hmac_digest as _hashlib_hmac_singleshot

    key: Py_buffer
    msg: Py_buffer
    digest: str

Single-shot HMAC.
[clinic start generated code]*/

static PyObject *
_hashlib_hmac_singleshot_impl(PyObject *module, Py_buffer *key,
                              Py_buffer *msg, const char *digest)
/*[clinic end generated code: output=15658ede5ab98185 input=019dffc571909a46]*/
{
    unsigned char md[EVP_MAX_MD_SIZE] = {0};
    unsigned int md_len = 0;
    unsigned char *result;
    PY_EVP_MD *evp;

    evp = py_digest_by_name(module, digest, Py_ht_mac);
    if (evp == NULL) {
        return NULL;
    }
    if (key->len > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "key is too long.");
        return NULL;
    }
    if (msg->len > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "msg is too long.");
        return NULL;
    }

    evp = py_digest_by_name(module, digest, Py_ht_mac);
    if (evp == NULL) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    result = HMAC(
        evp,
        (const void*)key->buf, (int)key->len,
        (const unsigned char*)msg->buf, (int)msg->len,
        md, &md_len
    );
    Py_END_ALLOW_THREADS
    PY_EVP_MD_free(evp);

    if (result == NULL) {
        _setException(PyExc_ValueError, NULL);
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char*)md, md_len);
}

/* OpenSSL-based HMAC implementation
 */

static int _hmac_update(HMACobject*, PyObject*);

/*[clinic input]
_hashlib.hmac_new

    key: Py_buffer
    msg as msg_obj: object(c_default="NULL") = b''
    digestmod: str(c_default="NULL") = None

Return a new hmac object.
[clinic start generated code]*/

static PyObject *
_hashlib_hmac_new_impl(PyObject *module, Py_buffer *key, PyObject *msg_obj,
                       const char *digestmod)
/*[clinic end generated code: output=9a35673be0cbea1b input=a0878868eb190134]*/
{
    PyTypeObject *type = get_hashlib_state(module)->HMACtype;
    PY_EVP_MD *digest;
    HMAC_CTX *ctx = NULL;
    HMACobject *self = NULL;
    int r;

    if (key->len > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "key is too long.");
        return NULL;
    }

    if ((digestmod == NULL) || !strlen(digestmod)) {
        PyErr_SetString(
            PyExc_TypeError, "Missing required parameter 'digestmod'.");
        return NULL;
    }

    digest = py_digest_by_name(module, digestmod, Py_ht_mac);
    if (!digest) {
        return NULL;
    }

    ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        _setException(PyExc_ValueError, NULL);
        goto error;
    }

    r = HMAC_Init_ex(
        ctx,
        (const char*)key->buf,
        (int)key->len,
        digest,
        NULL /*impl*/);
    PY_EVP_MD_free(digest);
    if (r == 0) {
        _setException(PyExc_ValueError, NULL);
        goto error;
    }

    self = (HMACobject *)PyObject_New(HMACobject, type);
    if (self == NULL) {
        goto error;
    }

    self->ctx = ctx;
    self->lock = NULL;

    if ((msg_obj != NULL) && (msg_obj != Py_None)) {
        if (!_hmac_update(self, msg_obj))
            goto error;
    }

    return (PyObject*)self;

error:
    if (ctx) HMAC_CTX_free(ctx);
    if (self) PyObject_Del(self);
    return NULL;
}

/* helper functions */
static int
locked_HMAC_CTX_copy(HMAC_CTX *new_ctx_p, HMACobject *self)
{
    int result;
    ENTER_HASHLIB(self);
    result = HMAC_CTX_copy(new_ctx_p, self->ctx);
    LEAVE_HASHLIB(self);
    return result;
}

static unsigned int
_hmac_digest_size(HMACobject *self)
{
    unsigned int digest_size = EVP_MD_size(HMAC_CTX_get_md(self->ctx));
    assert(digest_size <= EVP_MAX_MD_SIZE);
    return digest_size;
}

static int
_hmac_update(HMACobject *self, PyObject *obj)
{
    int r;
    Py_buffer view = {0};

    GET_BUFFER_VIEW_OR_ERROR(obj, &view, return 0);

    if (self->lock == NULL && view.len >= HASHLIB_GIL_MINSIZE) {
        self->lock = PyThread_allocate_lock();
        /* fail? lock = NULL and we fail over to non-threaded code. */
    }

    if (self->lock != NULL) {
        Py_BEGIN_ALLOW_THREADS
        PyThread_acquire_lock(self->lock, 1);
        r = HMAC_Update(self->ctx, (const unsigned char*)view.buf, view.len);
        PyThread_release_lock(self->lock);
        Py_END_ALLOW_THREADS
    } else {
        r = HMAC_Update(self->ctx, (const unsigned char*)view.buf, view.len);
    }

    PyBuffer_Release(&view);

    if (r == 0) {
        _setException(PyExc_ValueError, NULL);
        return 0;
    }
    return 1;
}

/*[clinic input]
_hashlib.HMAC.copy

Return a copy ("clone") of the HMAC object.
[clinic start generated code]*/

static PyObject *
_hashlib_HMAC_copy_impl(HMACobject *self)
/*[clinic end generated code: output=29aa28b452833127 input=e2fa6a05db61a4d6]*/
{
    HMACobject *retval;

    HMAC_CTX *ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        return _setException(PyExc_ValueError, NULL);
    }
    if (!locked_HMAC_CTX_copy(ctx, self)) {
        HMAC_CTX_free(ctx);
        return _setException(PyExc_ValueError, NULL);
    }

    retval = (HMACobject *)PyObject_New(HMACobject, Py_TYPE(self));
    if (retval == NULL) {
        HMAC_CTX_free(ctx);
        return NULL;
    }
    retval->ctx = ctx;
    retval->lock = NULL;

    return (PyObject *)retval;
}

static void
_hmac_dealloc(HMACobject *self)
{
    PyTypeObject *tp = Py_TYPE(self);
    if (self->lock != NULL) {
        PyThread_free_lock(self->lock);
    }
    HMAC_CTX_free(self->ctx);
    PyObject_Del(self);
    Py_DECREF(tp);
}

static PyObject *
_hmac_repr(HMACobject *self)
{
    PyObject *digest_name = py_digest_name(HMAC_CTX_get_md(self->ctx));
    if (digest_name == NULL) {
        return NULL;
    }
    PyObject *repr = PyUnicode_FromFormat(
        "<%U HMAC object @ %p>", digest_name, self
    );
    Py_DECREF(digest_name);
    return repr;
}

/*[clinic input]
_hashlib.HMAC.update
    msg: object

Update the HMAC object with msg.
[clinic start generated code]*/

static PyObject *
_hashlib_HMAC_update_impl(HMACobject *self, PyObject *msg)
/*[clinic end generated code: output=f31f0ace8c625b00 input=1829173bb3cfd4e6]*/
{
    if (!_hmac_update(self, msg)) {
        return NULL;
    }
    Py_RETURN_NONE;
}

static int
_hmac_digest(HMACobject *self, unsigned char *buf, unsigned int len)
{
    HMAC_CTX *temp_ctx = HMAC_CTX_new();
    if (temp_ctx == NULL) {
        PyErr_NoMemory();
        return 0;
    }
    if (!locked_HMAC_CTX_copy(temp_ctx, self)) {
        _setException(PyExc_ValueError, NULL);
        return 0;
    }
    int r = HMAC_Final(temp_ctx, buf, &len);
    HMAC_CTX_free(temp_ctx);
    if (r == 0) {
        _setException(PyExc_ValueError, NULL);
        return 0;
    }
    return 1;
}

/*[clinic input]
_hashlib.HMAC.digest
Return the digest of the bytes passed to the update() method so far.
[clinic start generated code]*/

static PyObject *
_hashlib_HMAC_digest_impl(HMACobject *self)
/*[clinic end generated code: output=1b1424355af7a41e input=bff07f74da318fb4]*/
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size = _hmac_digest_size(self);
    if (digest_size == 0) {
        return _setException(PyExc_ValueError, NULL);
    }
    int r = _hmac_digest(self, digest, digest_size);
    if (r == 0) {
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char *)digest, digest_size);
}

/*[clinic input]
_hashlib.HMAC.hexdigest

Return hexadecimal digest of the bytes passed to the update() method so far.

This may be used to exchange the value safely in email or other non-binary
environments.
[clinic start generated code]*/

static PyObject *
_hashlib_HMAC_hexdigest_impl(HMACobject *self)
/*[clinic end generated code: output=80d825be1eaae6a7 input=5abc42702874ddcf]*/
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size = _hmac_digest_size(self);
    if (digest_size == 0) {
        return _setException(PyExc_ValueError, NULL);
    }
    int r = _hmac_digest(self, digest, digest_size);
    if (r == 0) {
        return NULL;
    }
    return _Py_strhex((const char *)digest, digest_size);
}

static PyObject *
_hashlib_hmac_get_digest_size(HMACobject *self, void *closure)
{
    unsigned int digest_size = _hmac_digest_size(self);
    if (digest_size == 0) {
        return _setException(PyExc_ValueError, NULL);
    }
    return PyLong_FromLong(digest_size);
}

static PyObject *
_hashlib_hmac_get_block_size(HMACobject *self, void *closure)
{
    const EVP_MD *md = HMAC_CTX_get_md(self->ctx);
    if (md == NULL) {
        return _setException(PyExc_ValueError, NULL);
    }
    return PyLong_FromLong(EVP_MD_block_size(md));
}

static PyObject *
_hashlib_hmac_get_name(HMACobject *self, void *closure)
{
    PyObject *digest_name = py_digest_name(HMAC_CTX_get_md(self->ctx));
    if (digest_name == NULL) {
        return NULL;
    }
    PyObject *name = PyUnicode_FromFormat("hmac-%U", digest_name);
    Py_DECREF(digest_name);
    return name;
}

static PyMethodDef HMAC_methods[] = {
    _HASHLIB_HMAC_UPDATE_METHODDEF
    _HASHLIB_HMAC_DIGEST_METHODDEF
    _HASHLIB_HMAC_HEXDIGEST_METHODDEF
    _HASHLIB_HMAC_COPY_METHODDEF
    {NULL, NULL}  /* sentinel */
};

static PyGetSetDef HMAC_getset[] = {
    {"digest_size", (getter)_hashlib_hmac_get_digest_size, NULL, NULL, NULL},
    {"block_size", (getter)_hashlib_hmac_get_block_size, NULL, NULL, NULL},
    {"name", (getter)_hashlib_hmac_get_name, NULL, NULL, NULL},
    {NULL}  /* Sentinel */
};


PyDoc_STRVAR(hmactype_doc,
"The object used to calculate HMAC of a message.\n\
\n\
Methods:\n\
\n\
update() -- updates the current digest with an additional string\n\
digest() -- return the current digest value\n\
hexdigest() -- return the current digest as a string of hexadecimal digits\n\
copy() -- return a copy of the current hash object\n\
\n\
Attributes:\n\
\n\
name -- the name, including the hash algorithm used by this object\n\
digest_size -- number of bytes in digest() output\n");

static PyType_Slot HMACtype_slots[] = {
    {Py_tp_doc, (char *)hmactype_doc},
    {Py_tp_repr, (reprfunc)_hmac_repr},
    {Py_tp_dealloc,(destructor)_hmac_dealloc},
    {Py_tp_methods, HMAC_methods},
    {Py_tp_getset, HMAC_getset},
    {Py_tp_new, _disabled_new},
    {0, NULL}
};

PyType_Spec HMACtype_spec = {
    "_hashlib.HMAC",    /* name */
    sizeof(HMACobject),     /* basicsize */
    .flags = Py_TPFLAGS_DEFAULT,
    .slots = HMACtype_slots,
};


/* State for our callback function so that it can accumulate a result. */
typedef struct _internal_name_mapper_state {
    PyObject *set;
    int error;
} _InternalNameMapperState;


/* A callback function to pass to OpenSSL's OBJ_NAME_do_all(...) */
static void
_openssl_hash_name_mapper(const OBJ_NAME *openssl_obj_name, void *arg)
{
    _InternalNameMapperState *state = (_InternalNameMapperState *)arg;
    PyObject *py_name;

    assert(state != NULL);
    if (openssl_obj_name == NULL)
        return;
    /* Ignore aliased names, they pollute the list and OpenSSL appears to
     * have its own definition of alias as the resulting list still
     * contains duplicate and alternate names for several algorithms.     */
    if (openssl_obj_name->alias)
        return;

    py_name = PyUnicode_FromString(openssl_obj_name->name);
    if (py_name == NULL) {
        state->error = 1;
    } else {
        if (PySet_Add(state->set, py_name) != 0) {
            state->error = 1;
        }
        Py_DECREF(py_name);
    }
}


/* Ask OpenSSL for a list of supported ciphers, filling in a Python set. */
static PyObject*
generate_hash_name_list(void)
{
    _InternalNameMapperState state;
    state.set = PyFrozenSet_New(NULL);
    if (state.set == NULL)
        return NULL;
    state.error = 0;

    OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, &_openssl_hash_name_mapper, &state);

    if (state.error) {
        Py_DECREF(state.set);
        return NULL;
    }
    return state.set;
}


/*
 *  This macro generates constructor function definitions for specific
 *  hash algorithms.  These constructors are much faster than calling
 *  the generic one passing it a python string and are noticeably
 *  faster than calling a python new() wrapper.  That is important for
 *  code that wants to make hashes of a bunch of small strings.
 *  The first call will lazy-initialize, which reports an exception
 *  if initialization fails.
 */
#define GEN_CONSTRUCTOR(NAME)  \
    static PyObject * \
    EVP_new_ ## NAME (PyObject *self, PyObject *args) \
    { \
        PyObject *data_obj = NULL; \
        Py_buffer view = { 0 }; \
        PyObject *ret_obj; \
     \
        if (!PyArg_ParseTuple(args, "|O:" #NAME , &data_obj)) { \
            return NULL; \
        } \
     \
        if (CONST_new_ ## NAME ## _ctx_p == NULL) { \
            EVP_MD_CTX *ctx_p = EVP_MD_CTX_new(); \
            if (!EVP_get_digestbyname(#NAME) || \
                !EVP_DigestInit(ctx_p, EVP_get_digestbyname(#NAME))) { \
                _setException(PyExc_ValueError); \
                EVP_MD_CTX_free(ctx_p); \
                return NULL; \
            } \
            CONST_new_ ## NAME ## _ctx_p = ctx_p; \
        } \
     \
        if (data_obj) \
            GET_BUFFER_VIEW_OR_ERROUT(data_obj, &view); \
     \
        ret_obj = EVPnew( \
                    CONST_ ## NAME ## _name_obj, \
                    NULL, \
                    CONST_new_ ## NAME ## _ctx_p, \
                    (unsigned char*)view.buf, \
                    view.len); \
     \
        if (data_obj) \
            PyBuffer_Release(&view); \
        return ret_obj; \
    }

#ifndef LIBRESSL_VERSION_NUMBER
/*[clinic input]
_hashlib.get_fips_mode -> int

Determine the OpenSSL FIPS mode of operation.

For OpenSSL 3.0.0 and newer it returns the state of the default provider
in the default OSSL context. It's not quite the same as FIPS_mode() but good
enough for unittests.

Effectively any non-zero return value indicates FIPS mode;
values other than 1 may have additional significance.
[clinic start generated code]*/

static int
_hashlib_get_fips_mode_impl(PyObject *module)
/*[clinic end generated code: output=87eece1bab4d3fa9 input=2db61538c41c6fef]*/

{
    int result;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    result = EVP_default_properties_is_fips_enabled(NULL);
#else
    ERR_clear_error();
    result = FIPS_mode();
    if (result == 0) {
        // "If the library was built without support of the FIPS Object Module,
        // then the function will return 0 with an error code of
        // CRYPTO_R_FIPS_MODE_NOT_SUPPORTED (0x0f06d065)."
        // But 0 is also a valid result value.
        unsigned long errcode = ERR_peek_last_error();
        if (errcode) {
            _setException(PyExc_ValueError, NULL);
            return -1;
        }
    }
    return result;
#endif
}
#endif  // !LIBRESSL_VERSION_NUMBER

/* a PyMethodDef structure for the constructor */
#define CONSTRUCTOR_METH_DEF(NAME)  \
    {"openssl_" #NAME, (PyCFunction)EVP_new_ ## NAME, METH_VARARGS, \
        PyDoc_STR("Returns a " #NAME \
                  " hash object; optionally initialized with a string") \
    }

/* used in the init function to setup a constructor: initialize OpenSSL
   constructor constants if they haven't been initialized already.  */
#define INIT_CONSTRUCTOR_CONSTANTS(NAME)  do { \
    if (CONST_ ## NAME ## _name_obj == NULL) { \
        CONST_ ## NAME ## _name_obj = PyUnicode_FromString(#NAME); \
    } \
} while (0);

GEN_CONSTRUCTOR(md5)
GEN_CONSTRUCTOR(sha1)
GEN_CONSTRUCTOR(sha224)
GEN_CONSTRUCTOR(sha256)
GEN_CONSTRUCTOR(sha384)
GEN_CONSTRUCTOR(sha512)

/* List of functions exported by this module */

static struct PyMethodDef EVP_functions[] = {
    {"new", (PyCFunction)EVP_new, METH_VARARGS|METH_KEYWORDS, EVP_new__doc__},
#ifdef PY_PBKDF2_HMAC
    {"pbkdf2_hmac", (PyCFunction)pbkdf2_hmac, METH_VARARGS|METH_KEYWORDS,
     pbkdf2_hmac__doc__},
#endif
    _HASHLIB_SCRYPT_METHODDEF
    CONSTRUCTOR_METH_DEF(md5),
    CONSTRUCTOR_METH_DEF(sha1),
    CONSTRUCTOR_METH_DEF(sha224),
    CONSTRUCTOR_METH_DEF(sha256),
    CONSTRUCTOR_METH_DEF(sha384),
    CONSTRUCTOR_METH_DEF(sha512),
    {NULL,      NULL}            /* Sentinel */
};


/* Initialize this module. */

static int
hashlib_traverse(PyObject *m, visitproc visit, void *arg)
{
    _hashlibstate *state = get_hashlib_state(m);
    Py_VISIT(state->EVPtype);
    Py_VISIT(state->HMACtype);
#ifdef PY_OPENSSL_HAS_SHAKE
    Py_VISIT(state->EVPXOFtype);
#endif
    return 0;
}

static int
hashlib_clear(PyObject *m)
{
    _hashlibstate *state = get_hashlib_state(m);
    Py_CLEAR(state->EVPtype);
    Py_CLEAR(state->HMACtype);
#ifdef PY_OPENSSL_HAS_SHAKE
    Py_CLEAR(state->EVPXOFtype);
#endif
    if (state->hashtable != NULL) {
        _Py_hashtable_destroy(state->hashtable);
        state->hashtable = NULL;
    }
    return 0;
}

static void
hashlib_free(void *m)
{
    hashlib_clear((PyObject *)m);
}

/* Py_mod_exec functions */
static int
hashlib_openssl_legacy_init(PyObject *module)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
    /* Load all digest algorithms and initialize cpuid */
    OPENSSL_add_all_algorithms_noconf();
    ERR_load_crypto_strings();
#endif
    return 0;
}

static int
hashlib_init_hashtable(PyObject *module)
{
    _hashlibstate *state = get_hashlib_state(module);

    state->hashtable = py_hashentry_table_new();
    if (state->hashtable == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    return 0;
}

static int
hashlib_init_evptype(PyObject *module)
{
    _hashlibstate *state = get_hashlib_state(module);

    state->EVPtype = (PyTypeObject *)PyType_FromSpec(&EVPtype_spec);
    if (state->EVPtype == NULL) {
        return -1;
    }
    if (PyModule_AddType(module, state->EVPtype) < 0) {
        return -1;
    }
    return 0;
}

static int
hashlib_init_evpxoftype(PyObject *module)
{
#ifdef PY_OPENSSL_HAS_SHAKE
    _hashlibstate *state = get_hashlib_state(module);
    PyObject *bases;

    if (state->EVPtype == NULL) {
        return -1;
    }

    bases = PyTuple_Pack(1, state->EVPtype);
    if (bases == NULL) {
        return -1;
    }

    state->EVPXOFtype = (PyTypeObject *)PyType_FromSpecWithBases(
        &EVPXOFtype_spec, bases
    );
    Py_DECREF(bases);
    if (state->EVPXOFtype == NULL) {
        return -1;
    }
    if (PyModule_AddType(module, state->EVPXOFtype) < 0) {
        return -1;
    }
#endif
    return 0;
}

static int
hashlib_init_hmactype(PyObject *module)
{
    _hashlibstate *state = get_hashlib_state(module);

    state->HMACtype = (PyTypeObject *)PyType_FromSpec(&HMACtype_spec);
    if (state->HMACtype == NULL) {
        return -1;
    }
    if (PyModule_AddType(module, state->HMACtype) < 0) {
        return -1;
    }
    return 0;
}

#if 0
static PyModuleDef_Slot hashlib_slots[] = {
    /* OpenSSL 1.0.2 and LibreSSL */
    {Py_mod_exec, hashlib_openssl_legacy_init},
    {Py_mod_exec, hashlib_init_hashtable},
    {Py_mod_exec, hashlib_init_evptype},
    {Py_mod_exec, hashlib_init_evpxoftype},
    {Py_mod_exec, hashlib_init_hmactype},
    {Py_mod_exec, hashlib_md_meth_names},
    {0, NULL}
};
#endif

static struct PyModuleDef _hashlibmodule = {
    PyModuleDef_HEAD_INIT,
    "_hashlib",
    NULL,
    -1,
    EVP_functions,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit__hashlib(void)
{
    PyObject *m, *openssl_md_meth_names;

#ifndef OPENSSL_VERSION_1_1
    /* Load all digest algorithms and initialize cpuid */
    OPENSSL_add_all_algorithms_noconf();
    ERR_load_crypto_strings();
#endif

    /* TODO build EVP_functions openssl_* entries dynamically based
     * on what hashes are supported rather than listing many
     * but having some be unsupported.  Only init appropriate
     * constants. */

    Py_TYPE(&EVPtype) = &PyType_Type;
    if (PyType_Ready(&EVPtype) < 0)
        return NULL;

    m = PyModule_Create(&_hashlibmodule);
    if (m == NULL)
        return NULL;

    openssl_md_meth_names = generate_hash_name_list();
    if (openssl_md_meth_names == NULL) {
        Py_DECREF(m);
        return NULL;
    }
    if (hashlib_init_hashtable(m) < 0) {
        Py_DECREF(m);
        return NULL;
    }
    if (hashlib_init_evptype(m) < 0) {
        Py_DECREF(m);
        return NULL;
    }
    if (hashlib_init_evpxoftype(m) < 0) {
        Py_DECREF(m);
        return NULL;
    }
    if (hashlib_init_hmactype(m) < 0) {
        Py_DECREF(m);
        return NULL;
    }
    if (hashlib_md_meth_names(m) == -1) {
        Py_DECREF(m);
        return NULL;
    }

    Py_INCREF((PyObject *)&EVPtype);
    PyModule_AddObject(m, "HASH", (PyObject *)&EVPtype);

    /* these constants are used by the convenience constructors */
    INIT_CONSTRUCTOR_CONSTANTS(md5);
    INIT_CONSTRUCTOR_CONSTANTS(sha1);
    INIT_CONSTRUCTOR_CONSTANTS(sha224);
    INIT_CONSTRUCTOR_CONSTANTS(sha256);
    INIT_CONSTRUCTOR_CONSTANTS(sha384);
    INIT_CONSTRUCTOR_CONSTANTS(sha512);
    return m;
}
