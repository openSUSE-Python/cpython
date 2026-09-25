/* OpenSSL / LibreSSL compatibility layer shared by _ssl.c and _hashopenssl.c.
 *
 * Code in those modules is written against the OpenSSL 3.0 API.  When
 * building with OpenSSL 3.0 or newer nothing in this header maps a modern
 * name onto a deprecated one, so the 3.x build uses the 3.0 API only.  For
 * older libraries (OpenSSL 1.0.2, 1.1.x, LibreSSL) the missing modern names
 * are provided here as thin shims around the old API.
 *
 * Include this header after the OpenSSL headers.
 */

#ifndef Py_SSL_COMPAT_H
#define Py_SSL_COMPAT_H

#include <openssl/opensslv.h>
#include <openssl/crypto.h>

/* Library / API level detection */
#if defined(LIBRESSL_VERSION_NUMBER)
#  define PY_LIBRESSL 1
#  if LIBRESSL_VERSION_NUMBER >= 0x2070000fL
#    define PY_OPENSSL_1_1_API 1
#  endif
#else
#  if OPENSSL_VERSION_NUMBER < 0x10002000L
#    error "OpenSSL 1.0.2 or newer is required"
#  endif
#  if OPENSSL_VERSION_NUMBER >= 0x10100000L
#    define PY_OPENSSL_1_1_API 1
     /* Real OpenSSL 1.1+ (not merely the LibreSSL subset of its API) */
#    define PY_OPENSSL_1_1 1
#  endif
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
#    define PY_OPENSSL_1_1_1 1
#  endif
#  if OPENSSL_VERSION_NUMBER >= 0x30000000L
#    define PY_OPENSSL_3_API 1
#  endif
#  if OPENSSL_VERSION_NUMBER >= 0x30300000L
#    define PY_OPENSSL_3_3 1
#  endif
#endif

#ifndef PY_OPENSSL_1_1_API
#  define PY_OPENSSL_PRE_1_1 1
#endif

/* Names introduced in OpenSSL 1.1.0 (and LibreSSL 2.7.0) */
#ifdef PY_OPENSSL_PRE_1_1

#define OpenSSL_version_num SSLeay
#define OpenSSL_version SSLeay_version
#ifndef OPENSSL_VERSION
#  define OPENSSL_VERSION SSLEAY_VERSION
#endif

#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy

#define ASN1_STRING_get0_data ASN1_STRING_data
#define X509_get0_notBefore X509_get_notBefore
#define X509_get0_notAfter X509_get_notAfter

#endif /* PY_OPENSSL_PRE_1_1 */

/* SSL_get_peer_certificate() was renamed in OpenSSL 3.0 */
#ifndef PY_OPENSSL_3_API
#  define SSL_get1_peer_certificate SSL_get_peer_certificate
#endif

/* libssl accessors, only relevant for users of <openssl/ssl.h> */
#if defined(PY_OPENSSL_PRE_1_1) && defined(HEADER_SSL_H)

#define TLS_method SSLv23_method
#define TLS_client_method SSLv23_client_method
#define TLS_server_method SSLv23_server_method

static int X509_NAME_ENTRY_set(const X509_NAME_ENTRY *ne)
{
    return ne->set;
}

#ifndef OPENSSL_NO_COMP
/* LCOV_EXCL_START */
static int COMP_get_type(const COMP_METHOD *meth)
{
    return meth->type;
}
/* LCOV_EXCL_STOP */
#endif

static pem_password_cb *SSL_CTX_get_default_passwd_cb(SSL_CTX *ctx)
{
    return ctx->default_passwd_callback;
}

static void *SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX *ctx)
{
    return ctx->default_passwd_callback_userdata;
}

static int X509_OBJECT_get_type(X509_OBJECT *x)
{
    return x->type;
}

static X509 *X509_OBJECT_get0_X509(X509_OBJECT *x)
{
    return x->data.x509;
}

static int BIO_up_ref(BIO *b)
{
    CRYPTO_add(&b->references, 1, CRYPTO_LOCK_BIO);
    return 1;
}

static STACK_OF(X509_OBJECT) *X509_STORE_get0_objects(X509_STORE *store)
{
    return store->objs;
}

static X509_VERIFY_PARAM *X509_STORE_get0_param(X509_STORE *store)
{
    return store->param;
}

static int SSL_SESSION_has_ticket(const SSL_SESSION *s)
{
    return (s->tlsext_ticklen > 0) ? 1 : 0;
}

static unsigned long
SSL_SESSION_get_ticket_lifetime_hint(const SSL_SESSION *s)
{
    return s->tlsext_tick_lifetime_hint;
}

#endif /* PY_OPENSSL_PRE_1_1 && HEADER_SSL_H */

#endif /* Py_SSL_COMPAT_H */
