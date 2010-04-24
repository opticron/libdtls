module gnutls;
/* -*- c -*-
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Free Software Foundation
 *
 * Author: Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 *
 */

/* This file contains the types and prototypes for all the
 * high level functionality of gnutls main library. For the
 * extra functionality (which is under the GNU GPL license) check
 * the gnutls/extra.h header. The openssl compatibility layer is
 * in gnutls/openssl.h.
 *
 * The low level cipher functionality is in libgcrypt. Check
 * gcrypt.h
 */
version (build) {
	    pragma(link, "gnutls");
}

/* Get size_t. */
import std.c.stddef;
/* Get ssize_t. */
alias int ssize_t;
/* Get time_t. */
import std.c.time;

extern(C) {

const string GNUTLS_VERSION = "2.8.5";

const int GNUTLS_VERSION_MAJOR = 2;
const int GNUTLS_VERSION_MINOR = 8;
const int GNUTLS_VERSION_PATCH = 5;

const int GNUTLS_VERSION_NUMBER = 0x020805;


  enum gnutls_cipher_algorithm
  {
    GNUTLS_CIPHER_UNKNOWN = 0,
    GNUTLS_CIPHER_NULL = 1,
    GNUTLS_CIPHER_ARCFOUR_128,
    GNUTLS_CIPHER_3DES_CBC,
    GNUTLS_CIPHER_AES_128_CBC,
    GNUTLS_CIPHER_AES_256_CBC,
    GNUTLS_CIPHER_ARCFOUR_40,
    GNUTLS_CIPHER_CAMELLIA_128_CBC,
    GNUTLS_CIPHER_CAMELLIA_256_CBC,
    GNUTLS_CIPHER_RC2_40_CBC = 90,
    GNUTLS_CIPHER_DES_CBC,

    /* used only for PGP internals. Ignored in TLS/SSL 
     */
    GNUTLS_CIPHER_IDEA_PGP_CFB = 200,
    GNUTLS_CIPHER_3DES_PGP_CFB,
    GNUTLS_CIPHER_CAST5_PGP_CFB,
    GNUTLS_CIPHER_BLOWFISH_PGP_CFB,
    GNUTLS_CIPHER_SAFER_SK128_PGP_CFB,
    GNUTLS_CIPHER_AES128_PGP_CFB,
    GNUTLS_CIPHER_AES192_PGP_CFB,
    GNUTLS_CIPHER_AES256_PGP_CFB,
    GNUTLS_CIPHER_TWOFISH_PGP_CFB
  };
alias gnutls_cipher_algorithm.GNUTLS_CIPHER_AES_128_CBC GNUTLS_CIPHER_RIJNDAEL_128_CBC;
alias gnutls_cipher_algorithm.GNUTLS_CIPHER_AES_256_CBC GNUTLS_CIPHER_RIJNDAEL_256_CBC;
alias gnutls_cipher_algorithm.GNUTLS_CIPHER_AES_128_CBC GNUTLS_CIPHER_RIJNDAEL_CBC;
alias gnutls_cipher_algorithm.GNUTLS_CIPHER_ARCFOUR_128 GNUTLS_CIPHER_ARCFOUR;

  enum gnutls_kx_algorithm_t
  {
    GNUTLS_KX_UNKNOWN = 0,
    GNUTLS_KX_RSA = 1,
    GNUTLS_KX_DHE_DSS,
    GNUTLS_KX_DHE_RSA,
    GNUTLS_KX_ANON_DH,
    GNUTLS_KX_SRP,
    GNUTLS_KX_RSA_EXPORT,
    GNUTLS_KX_SRP_RSA,
    GNUTLS_KX_SRP_DSS,
    GNUTLS_KX_PSK,
    GNUTLS_KX_DHE_PSK
  };

  enum gnutls_params_type_t
  {
    GNUTLS_PARAMS_RSA_EXPORT = 1,
    GNUTLS_PARAMS_DH
  };

  enum gnutls_credentials_type_t
  {
    GNUTLS_CRD_CERTIFICATE = 1,
    GNUTLS_CRD_ANON,
    GNUTLS_CRD_SRP,
    GNUTLS_CRD_PSK,
    GNUTLS_CRD_IA
  };
  alias gnutls_credentials_type_t.GNUTLS_CRD_CERTIFICATE GNUTLS_CRD_CERTIFICATE;
  alias gnutls_credentials_type_t.GNUTLS_CRD_ANON GNUTLS_CRD_ANON;
  alias gnutls_credentials_type_t.GNUTLS_CRD_SRP GNUTLS_CRD_SRP;
  alias gnutls_credentials_type_t.GNUTLS_CRD_PSK GNUTLS_CRD_PSK;
  alias gnutls_credentials_type_t.GNUTLS_CRD_IA GNUTLS_CRD_IA;


  enum gnutls_mac_algorithm_t
  {
    GNUTLS_MAC_UNKNOWN = 0,
    GNUTLS_MAC_NULL = 1,
    GNUTLS_MAC_MD5,
    GNUTLS_MAC_SHA1,
    GNUTLS_MAC_RMD160,
    GNUTLS_MAC_MD2,
    GNUTLS_MAC_SHA256,
    GNUTLS_MAC_SHA384,
    GNUTLS_MAC_SHA512
    /* If you add anything here, make sure you align with
       gnutls_digest_algorithm_t, in particular SHA-224. */
  }
alias gnutls_mac_algorithm_t.GNUTLS_MAC_SHA1 GNUTLS_MAC_SHA;

  /* The enumerations here should have the same value with
     gnutls_mac_algorithm_t.
   */
  enum gnutls_digest_algorithm_t
  {
    GNUTLS_DIG_NULL = gnutls_mac_algorithm_t.GNUTLS_MAC_NULL,
    GNUTLS_DIG_MD5 = gnutls_mac_algorithm_t.GNUTLS_MAC_MD5,
    GNUTLS_DIG_SHA1 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA1,
    GNUTLS_DIG_RMD160 = gnutls_mac_algorithm_t.GNUTLS_MAC_RMD160,
    GNUTLS_DIG_MD2 = gnutls_mac_algorithm_t.GNUTLS_MAC_MD2,
    GNUTLS_DIG_SHA256 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA256,
    GNUTLS_DIG_SHA384 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA384,
    GNUTLS_DIG_SHA512 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA512,
    GNUTLS_DIG_SHA224
  }
alias gnutls_digest_algorithm_t.GNUTLS_DIG_SHA1 GNUTLS_DIG_SHA;

  /* exported for other gnutls headers. This is the maximum number of
   * algorithms (ciphers, kx or macs).
   */
const int GNUTLS_MAX_ALGORITHM_NUM = 16;

  enum gnutls_compression_method_t
  {
    GNUTLS_COMP_UNKNOWN = 0,
    GNUTLS_COMP_NULL = 1,
    GNUTLS_COMP_DEFLATE,
    GNUTLS_COMP_LZO		/* only available if gnutls-extra has
				   been initialized
				 */
  };
alias gnutls_compression_method_t.GNUTLS_COMP_DEFLATE GNUTLS_COMP_ZLIB;

  enum gnutls_connection_end_t
  {
    GNUTLS_SERVER = 1,
    GNUTLS_CLIENT
  }
  alias gnutls_connection_end_t.GNUTLS_SERVER GNUTLS_SERVER;
  alias gnutls_connection_end_t.GNUTLS_CLIENT GNUTLS_CLIENT;

  enum gnutls_alert_level_t
  {
    GNUTLS_AL_WARNING = 1,
    GNUTLS_AL_FATAL
  };

  enum gnutls_alert_description_t
  {
    GNUTLS_A_CLOSE_NOTIFY,
    GNUTLS_A_UNEXPECTED_MESSAGE = 10,
    GNUTLS_A_BAD_RECORD_MAC = 20,
    GNUTLS_A_DECRYPTION_FAILED,
    GNUTLS_A_RECORD_OVERFLOW,
    GNUTLS_A_DECOMPRESSION_FAILURE = 30,
    GNUTLS_A_HANDSHAKE_FAILURE = 40,
    GNUTLS_A_SSL3_NO_CERTIFICATE = 41,
    GNUTLS_A_BAD_CERTIFICATE = 42,
    GNUTLS_A_UNSUPPORTED_CERTIFICATE,
    GNUTLS_A_CERTIFICATE_REVOKED,
    GNUTLS_A_CERTIFICATE_EXPIRED,
    GNUTLS_A_CERTIFICATE_UNKNOWN,
    GNUTLS_A_ILLEGAL_PARAMETER,
    GNUTLS_A_UNKNOWN_CA,
    GNUTLS_A_ACCESS_DENIED,
    GNUTLS_A_DECODE_ERROR = 50,
    GNUTLS_A_DECRYPT_ERROR,
    GNUTLS_A_EXPORT_RESTRICTION = 60,
    GNUTLS_A_PROTOCOL_VERSION = 70,
    GNUTLS_A_INSUFFICIENT_SECURITY,
    GNUTLS_A_INTERNAL_ERROR = 80,
    GNUTLS_A_USER_CANCELED = 90,
    GNUTLS_A_NO_RENEGOTIATION = 100,
    GNUTLS_A_UNSUPPORTED_EXTENSION = 110,
    GNUTLS_A_CERTIFICATE_UNOBTAINABLE = 111,
    GNUTLS_A_UNRECOGNIZED_NAME = 112,
    GNUTLS_A_UNKNOWN_PSK_IDENTITY = 115,
    GNUTLS_A_INNER_APPLICATION_FAILURE = 208,
    GNUTLS_A_INNER_APPLICATION_VERIFICATION = 209
  };
  alias gnutls_alert_description_t.GNUTLS_A_UNKNOWN_PSK_IDENTITY GNUTLS_A_UNKNOWN_PSK_IDENTITY;

  enum gnutls_handshake_description_t
  { GNUTLS_HANDSHAKE_HELLO_REQUEST = 0,
    GNUTLS_HANDSHAKE_CLIENT_HELLO = 1,
    GNUTLS_HANDSHAKE_SERVER_HELLO = 2,
    GNUTLS_HANDSHAKE_CERTIFICATE_PKT = 11,
    GNUTLS_HANDSHAKE_SERVER_KEY_EXCHANGE = 12,
    GNUTLS_HANDSHAKE_CERTIFICATE_REQUEST = 13,
    GNUTLS_HANDSHAKE_SERVER_HELLO_DONE = 14,
    GNUTLS_HANDSHAKE_CERTIFICATE_VERIFY = 15,
    GNUTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE = 16,
    GNUTLS_HANDSHAKE_FINISHED = 20,
    GNUTLS_HANDSHAKE_SUPPLEMENTAL = 23
  };

/* Note that the status bits have different meanings
 * in openpgp keys and x.509 certificate verification.
 */
  enum gnutls_certificate_status_t
  {
    GNUTLS_CERT_INVALID = 2,	/* will be set if the certificate
				 * was not verified.
				 */
    GNUTLS_CERT_REVOKED = 32,	/* in X.509 this will be set only if CRLs are checked
				 */

    /* Those are extra information about the verification
     * process. Will be set only if the certificate was 
     * not verified.
     */
    GNUTLS_CERT_SIGNER_NOT_FOUND = 64,
    GNUTLS_CERT_SIGNER_NOT_CA = 128,
    GNUTLS_CERT_INSECURE_ALGORITHM = 256,

    /* Time verification.
     */
    GNUTLS_CERT_NOT_ACTIVATED = 512,
    GNUTLS_CERT_EXPIRED = 1024

  };

  enum gnutls_certificate_request_t
  {
    GNUTLS_CERT_IGNORE,
    GNUTLS_CERT_REQUEST = 1,
    GNUTLS_CERT_REQUIRE
  };

  enum gnutls_openpgp_crt_status_t
  { GNUTLS_OPENPGP_CERT,
    GNUTLS_OPENPGP_CERT_FINGERPRINT
  };
  alias gnutls_openpgp_crt_status_t.GNUTLS_OPENPGP_CERT GNUTLS_OPENPGP_CERT;
  alias gnutls_openpgp_crt_status_t.GNUTLS_OPENPGP_CERT_FINGERPRINT GNUTLS_OPENPGP_CERT_FINGERPRINT;

  enum gnutls_close_request_t
  {
    GNUTLS_SHUT_RDWR = 0,
    GNUTLS_SHUT_WR = 1
  }
alias gnutls_close_request_t.GNUTLS_SHUT_RDWR GNUTLS_SHUT_RDWR;
alias gnutls_close_request_t.GNUTLS_SHUT_WR GNUTLS_SHUT_WR;

  enum gnutls_protocol_t
  {
    GNUTLS_SSL3 = 1,
    GNUTLS_TLS1_0,
    GNUTLS_TLS1_1,
    GNUTLS_TLS1_2,
    GNUTLS_VERSION_UNKNOWN = 0xff
  }
alias gnutls_protocol_t.GNUTLS_TLS1_0 GNUTLS_TLS1;

  enum gnutls_certificate_type_t
  {
    GNUTLS_CRT_UNKNOWN = 0,
    GNUTLS_CRT_X509 = 1,
    GNUTLS_CRT_OPENPGP
  }

  enum gnutls_x509_crt_fmt_t
  {
    GNUTLS_X509_FMT_DER,
    GNUTLS_X509_FMT_PEM
  }
alias gnutls_x509_crt_fmt_t.GNUTLS_X509_FMT_PEM GNUTLS_X509_FMT_PEM;
alias gnutls_x509_crt_fmt_t.GNUTLS_X509_FMT_DER GNUTLS_X509_FMT_DER;

  enum gnutls_certificate_print_formats
    {
      GNUTLS_CRT_PRINT_FULL,
      GNUTLS_CRT_PRINT_ONELINE,
      GNUTLS_CRT_PRINT_UNSIGNED_FULL
    } ;
  alias gnutls_certificate_print_formats gnutls_certificate_print_formats_t;
  alias gnutls_certificate_print_formats.GNUTLS_CRT_PRINT_FULL GNUTLS_CRT_PRINT_FULL;
  alias gnutls_certificate_print_formats.GNUTLS_CRT_PRINT_ONELINE GNUTLS_CRT_PRINT_ONELINE;
  alias gnutls_certificate_print_formats.GNUTLS_CRT_PRINT_UNSIGNED_FULL GNUTLS_CRT_PRINT_UNSIGNED_FULL;

  enum gnutls_pk_algorithm_t
  {
    GNUTLS_PK_UNKNOWN = 0,
    GNUTLS_PK_RSA = 1,
    GNUTLS_PK_DSA
  };

  char *gnutls_pk_algorithm_get_name (gnutls_pk_algorithm_t algorithm);

  enum gnutls_sign_algorithm_t
  {
    GNUTLS_SIGN_UNKNOWN = 0,
    GNUTLS_SIGN_RSA_SHA1 = 1,
    GNUTLS_SIGN_DSA_SHA1,
    GNUTLS_SIGN_RSA_MD5,
    GNUTLS_SIGN_RSA_MD2,
    GNUTLS_SIGN_RSA_RMD160,
    GNUTLS_SIGN_RSA_SHA256,
    GNUTLS_SIGN_RSA_SHA384,
    GNUTLS_SIGN_RSA_SHA512,
    GNUTLS_SIGN_RSA_SHA224
  };
alias gnutls_sign_algorithm_t.GNUTLS_SIGN_RSA_SHA1 GNUTLS_SIGN_RSA_SHA;
alias gnutls_sign_algorithm_t.GNUTLS_SIGN_DSA_SHA1 GNUTLS_SIGN_DSA_SHA;

  char *
  gnutls_sign_algorithm_get_name (gnutls_sign_algorithm_t sign);

/* If you want to change this, then also change the define in
 * gnutls_int.h, and recompile.
 */
  alias void *gnutls_transport_ptr_t;

  // XXX forward ref errors!
  struct gnutls_session_int;
  alias gnutls_session_int *gnutls_session_t;

  struct gnutls_dh_params_int;
  alias gnutls_dh_params_int *gnutls_dh_params_t;

  /* XXX ugly. */
  struct gnutls_x509_privkey_int;
  alias gnutls_x509_privkey_int *gnutls_rsa_params_t;

  struct gnutls_priority_st;
  alias gnutls_priority_st *gnutls_priority_t;

  struct gnutls_datum_t
  {
    char *data;
    uint size;
  };


  struct gnutls_params_st
  {
    gnutls_params_type_t type;
    union params
    {
      gnutls_dh_params_t dh;
      gnutls_rsa_params_t rsa_export;
    };
    int deinit;
  };

  alias int gnutls_params_function (gnutls_session_t, gnutls_params_type_t,
				      gnutls_params_st *);

/* internal functions */

  int gnutls_init (gnutls_session_t * session,
		   gnutls_connection_end_t con_end);
  void gnutls_deinit (gnutls_session_t session);
alias gnutls_deinit _gnutls_deinit;

  int gnutls_bye (gnutls_session_t session, gnutls_close_request_t how);

  int gnutls_handshake (gnutls_session_t session);
  int gnutls_rehandshake (gnutls_session_t session);

  gnutls_alert_description_t gnutls_alert_get (gnutls_session_t session);
  int gnutls_alert_send (gnutls_session_t session,
			 gnutls_alert_level_t level,
			 gnutls_alert_description_t desc);
  int gnutls_alert_send_appropriate (gnutls_session_t session, int err);
  char *gnutls_alert_get_name (gnutls_alert_description_t alert);

/* get information on the current session */
  gnutls_cipher_algorithm_t gnutls_cipher_get (gnutls_session_t session);
  gnutls_kx_algorithm_t gnutls_kx_get (gnutls_session_t session);
  gnutls_mac_algorithm_t gnutls_mac_get (gnutls_session_t session);
  gnutls_compression_method_t
  gnutls_compression_get (gnutls_session_t session);
  gnutls_certificate_type_t
  gnutls_certificate_type_get (gnutls_session_t session);

  size_t gnutls_cipher_get_key_size (gnutls_cipher_algorithm_t algorithm);
  size_t gnutls_mac_get_key_size (gnutls_mac_algorithm_t algorithm);

/* the name of the specified algorithms */
  char *gnutls_cipher_get_name (gnutls_cipher_algorithm_t algorithm);
  char *gnutls_mac_get_name (gnutls_mac_algorithm_t algorithm);
  char *
  gnutls_compression_get_name (gnutls_compression_method_t algorithm);
  char *gnutls_kx_get_name (gnutls_kx_algorithm_t algorithm);
  char *
  gnutls_certificate_type_get_name (gnutls_certificate_type_t type);
  char *gnutls_pk_get_name (gnutls_pk_algorithm_t algorithm);
  char *gnutls_sign_get_name (gnutls_sign_algorithm_t algorithm);

  gnutls_mac_algorithm_t gnutls_mac_get_id (char* name);
  gnutls_compression_method_t gnutls_compression_get_id (char* name);
  gnutls_cipher_algorithm_t gnutls_cipher_get_id (char* name);
  gnutls_kx_algorithm_t gnutls_kx_get_id (char* name);
  gnutls_protocol_t gnutls_protocol_get_id (char* name);
  gnutls_certificate_type_t gnutls_certificate_type_get_id (char* name);
  gnutls_pk_algorithm_t gnutls_pk_get_id (char *name);
  gnutls_sign_algorithm_t gnutls_sign_get_id (char *name);

  /* list supported algorithms */
  gnutls_cipher_algorithm_t *gnutls_cipher_list ();
  gnutls_mac_algorithm_t *gnutls_mac_list ();
  gnutls_compression_method_t *gnutls_compression_list ();
  gnutls_protocol_t *gnutls_protocol_list ();
  gnutls_certificate_type_t *gnutls_certificate_type_list ();
  gnutls_kx_algorithm_t *gnutls_kx_list ();
  gnutls_pk_algorithm_t *gnutls_pk_list ();
  gnutls_sign_algorithm_t *gnutls_sign_list ();
  char *gnutls_cipher_suite_info (size_t idx,
					char *cs_id,
					gnutls_kx_algorithm_t *kx,
					gnutls_cipher_algorithm_t *cipher,
					gnutls_mac_algorithm_t *mac,
					gnutls_protocol_t *vers);

  /* error functions */
  int gnutls_error_is_fatal (int error);
  int gnutls_error_to_alert (int err, int *level);

  void gnutls_perror (int error);
  char *gnutls_strerror (int error);
  char *gnutls_strerror_name (int error);

/* Semi-internal functions.
 */
  void gnutls_handshake_set_private_extensions (gnutls_session_t session,
						int allow);
  gnutls_handshake_description_t
  gnutls_handshake_get_last_out (gnutls_session_t session);
  gnutls_handshake_description_t
  gnutls_handshake_get_last_in (gnutls_session_t session);

/* Record layer functions.
 */
  ssize_t gnutls_record_send (gnutls_session_t session, void *data,
			      size_t sizeofdata);
  ssize_t gnutls_record_recv (gnutls_session_t session, void *data,
			      size_t sizeofdata);
alias gnutls_record_recv gnutls_read;
alias gnutls_record_send gnutls_write;

  void gnutls_session_enable_compatibility_mode (gnutls_session_t session);

  void gnutls_record_disable_padding (gnutls_session_t session);

  int gnutls_record_get_direction (gnutls_session_t session);

  size_t gnutls_record_get_max_size (gnutls_session_t session);
  ssize_t gnutls_record_set_max_size (gnutls_session_t session, size_t size);

  size_t gnutls_record_check_pending (gnutls_session_t session);

  int gnutls_prf (gnutls_session_t session,
		  size_t label_size, char *label,
		  int server_random_first,
		  size_t extra_size, char *extra,
		  size_t outsize, char *data_out);

  int gnutls_prf_raw (gnutls_session_t session,
		      size_t label_size, char *label,
		      size_t seed_size, char *seed,
		      size_t outsize, char *data_out);

/* TLS Extensions */

  alias int (*gnutls_ext_recv_func) (gnutls_session_t session,
				       char *data, size_t len);
  alias int (*gnutls_ext_send_func) (gnutls_session_t session,
				       char *data, size_t len);

  /* This flag indicates for an extension whether
   * it is useful to application level or TLS level only.
   * This is (only) used to parse the application level extensions
   * before the user_hello callback is called.
   */
  enum gnutls_ext_parse_type_t
    {
      GNUTLS_EXT_ANY,
      GNUTLS_EXT_APPLICATION,
      GNUTLS_EXT_TLS
    };

  int gnutls_ext_register (int type,
			   char *name,
			   gnutls_ext_parse_type_t parse_type,
			   gnutls_ext_recv_func recv_func,
			   gnutls_ext_send_func send_func);

  enum gnutls_server_name_type_t
  {
    GNUTLS_NAME_DNS = 1
  };

  int gnutls_server_name_set (gnutls_session_t session,
			      gnutls_server_name_type_t type,
			      void *name, size_t name_length);

  int gnutls_server_name_get (gnutls_session_t session,
			      void *data, size_t * data_length,
			      uint *type, uint indx);

  /* Opaque PRF Input
   * http://tools.ietf.org/id/draft-rescorla-tls-opaque-prf-input-00.txt
   */

  void
  gnutls_oprfi_enable_client (gnutls_session_t session,
			      size_t len,
			      char *data);

  alias int (*gnutls_oprfi_callback_func) (gnutls_session_t session,
					     void *userdata,
					     size_t oprfi_len,
					     char *in_oprfi,
					     char *out_oprfi);

  void
  gnutls_oprfi_enable_server (gnutls_session_t session,
			      gnutls_oprfi_callback_func cb,
			      void *userdata);

  /* Supplemental data, RFC 4680. */
  enum gnutls_supplemental_data_format_type_t
    {
      GNUTLS_SUPPLEMENTAL_USER_MAPPING_DATA = 0
    };

  char *gnutls_supplemental_get_name
  (gnutls_supplemental_data_format_type_t type);

/* functions to set priority of cipher suites 
 */
  int gnutls_cipher_set_priority (gnutls_session_t session, int *list);
  int gnutls_mac_set_priority (gnutls_session_t session, int *list);
  int gnutls_compression_set_priority (gnutls_session_t session,
				       int *list);
  int gnutls_kx_set_priority (gnutls_session_t session, int *list);
  int gnutls_protocol_set_priority (gnutls_session_t session,
				    int *list);
  int gnutls_certificate_type_set_priority (gnutls_session_t session,
					    int *list);

/* if you just want some defaults, use the following.
 */
  int gnutls_priority_init (gnutls_priority_t *priority_cache,
			    char *priorities,
			    char** err_pos);
  void gnutls_priority_deinit (gnutls_priority_t priority_cache);

  int gnutls_priority_set (gnutls_session_t session,
			   gnutls_priority_t priority);
  int gnutls_priority_set_direct (gnutls_session_t session,
				  char *priorities,
				  char** err_pos);

  /* for compatibility
   */
  int gnutls_set_default_priority (gnutls_session_t session);
  int gnutls_set_default_export_priority (gnutls_session_t session);

/* Returns the name of a cipher suite */
  char *
  gnutls_cipher_suite_get_name (gnutls_kx_algorithm_t kx_algorithm,
				gnutls_cipher_algorithm_t cipher_algorithm,
				gnutls_mac_algorithm_t mac_algorithm);

/* get the currently used protocol version */
  gnutls_protocol_t gnutls_protocol_get_version (gnutls_session_t session);

  char *gnutls_protocol_get_name (gnutls_protocol_t vers);


/* get/set session 
 */
  int gnutls_session_set_data (gnutls_session_t session,
			       void *session_data,
			       size_t session_data_size);
  int gnutls_session_get_data (gnutls_session_t session, void *session_data,
			       size_t * session_data_size);
  int gnutls_session_get_data2 (gnutls_session_t session,
				gnutls_datum_t * data);

/* returns the session ID */
const int GNUTLS_MAX_SESSION_ID = 32;
  int gnutls_session_get_id (gnutls_session_t session, void *session_id,
			     size_t * session_id_size);

/* returns security values. 
 * Do not use them unless you know what you're doing.
 */
const int GNUTLS_MASTER_SIZE = 48;
const int GNUTLS_RANDOM_SIZE = 32;
  void *gnutls_session_get_server_random (gnutls_session_t session);
  void *gnutls_session_get_client_random (gnutls_session_t session);
  void *gnutls_session_get_master_secret (gnutls_session_t session);

  alias void (*gnutls_finished_callback_func) (gnutls_session_t session,
						 void *finished,
						 size_t len);
  void
  gnutls_session_set_finished_function (gnutls_session_t session,
					gnutls_finished_callback_func func);

/* checks if this session is a resumed one 
 */
  int gnutls_session_is_resumed (gnutls_session_t session);

  alias int (*gnutls_db_store_func) (void *, gnutls_datum_t key,
				       gnutls_datum_t data);
  alias int (*gnutls_db_remove_func) (void *, gnutls_datum_t key);
  alias gnutls_datum_t (*gnutls_db_retr_func) (void *, gnutls_datum_t key);

  void gnutls_db_set_cache_expiration (gnutls_session_t session, int seconds);

  void gnutls_db_remove_session (gnutls_session_t session);
  void gnutls_db_set_retrieve_function (gnutls_session_t session,
					gnutls_db_retr_func retr_func);
  void gnutls_db_set_remove_function (gnutls_session_t session,
				      gnutls_db_remove_func rem_func);
  void gnutls_db_set_store_function (gnutls_session_t session,
				     gnutls_db_store_func store_func);
  void gnutls_db_set_ptr (gnutls_session_t session, void *ptr);
  void *gnutls_db_get_ptr (gnutls_session_t session);
  int gnutls_db_check_entry (gnutls_session_t session,
			     gnutls_datum_t session_entry);

  alias int (*gnutls_handshake_post_client_hello_func)(gnutls_session_t);
  void
  gnutls_handshake_set_post_client_hello_function(gnutls_session_t session,
						  gnutls_handshake_post_client_hello_func func);

  void gnutls_handshake_set_max_packet_length (gnutls_session_t session,
					       size_t max);

/* returns libgnutls version (call it with a NULL argument)
 */
  char *gnutls_check_version (char *req_version);

/* Functions for setting/clearing credentials
 */
  void gnutls_credentials_clear (gnutls_session_t session);

/* cred is a structure defined by the kx algorithm
 */
  int gnutls_credentials_set (gnutls_session_t session,
			      gnutls_credentials_type_t type, void *cred);
alias gnutls_credentials_set gnutls_cred_set;

/* Credential structures - used in gnutls_credentials_set(); */

  struct gnutls_certificate_credentials_st;
  alias gnutls_certificate_credentials_st
    *gnutls_certificate_credentials_t;
  alias gnutls_certificate_credentials_t
    gnutls_certificate_server_credentials;
  alias gnutls_certificate_credentials_t
    gnutls_certificate_client_credentials;

  struct gnutls_anon_server_credentials_st;
  alias gnutls_anon_server_credentials_st
    *gnutls_anon_server_credentials_t;
  struct gnutls_anon_client_credentials_st;
  alias gnutls_anon_client_credentials_st
    *gnutls_anon_client_credentials_t;

  void gnutls_anon_free_server_credentials (gnutls_anon_server_credentials_t sc);
  int gnutls_anon_allocate_server_credentials (gnutls_anon_server_credentials_t * sc);

  void gnutls_anon_set_server_dh_params (gnutls_anon_server_credentials_t res,
					 gnutls_dh_params_t dh_params);

  void
  gnutls_anon_set_server_params_function (gnutls_anon_server_credentials_t res,
					  gnutls_params_function * func);

  void
  gnutls_anon_free_client_credentials (gnutls_anon_client_credentials_t sc);
  int
  gnutls_anon_allocate_client_credentials (gnutls_anon_client_credentials_t * sc);

/* CERTFILE is an x509 certificate in PEM form.
 * KEYFILE is a pkcs-1 private key in PEM form (for RSA keys).
 */
  void
  gnutls_certificate_free_credentials (gnutls_certificate_credentials_t sc);
  int
  gnutls_certificate_allocate_credentials (gnutls_certificate_credentials_t *res);

  void gnutls_certificate_free_keys (gnutls_certificate_credentials_t sc);
  void gnutls_certificate_free_cas (gnutls_certificate_credentials_t sc);
  void gnutls_certificate_free_ca_names (gnutls_certificate_credentials_t sc);
  void gnutls_certificate_free_crls (gnutls_certificate_credentials_t sc);

  void gnutls_certificate_set_dh_params (gnutls_certificate_credentials_t res,
					 gnutls_dh_params_t dh_params);
  void
  gnutls_certificate_set_rsa_export_params (gnutls_certificate_credentials_t res,
					    gnutls_rsa_params_t rsa_params);
  void
  gnutls_certificate_set_verify_flags (gnutls_certificate_credentials_t res,
				       uint flags);
  void
  gnutls_certificate_set_verify_limits (gnutls_certificate_credentials_t res,
					uint max_bits,
					uint max_depth);

  int
  gnutls_certificate_set_x509_trust_file (gnutls_certificate_credentials_t res,
					  char *cafile,
					  gnutls_x509_crt_fmt_t type);
  int
  gnutls_certificate_set_x509_trust_mem (gnutls_certificate_credentials_t res,
					 gnutls_datum_t * ca,
					 gnutls_x509_crt_fmt_t type);

  int
  gnutls_certificate_set_x509_crl_file (gnutls_certificate_credentials_t res,
					char *crlfile,
					gnutls_x509_crt_fmt_t type);
  int
  gnutls_certificate_set_x509_crl_mem (gnutls_certificate_credentials_t res,
				       gnutls_datum_t * CRL,
				       gnutls_x509_crt_fmt_t type);

  int
  gnutls_certificate_set_x509_key_file (gnutls_certificate_credentials_t res,
					char *certfile,
					char *keyfile,
					gnutls_x509_crt_fmt_t type);
  int
  gnutls_certificate_set_x509_key_mem (gnutls_certificate_credentials_t res,
				       gnutls_datum_t * cert,
				       gnutls_datum_t * key,
				       gnutls_x509_crt_fmt_t type);

  void gnutls_certificate_send_x509_rdn_sequence (gnutls_session_t session,
						  int status);

  int gnutls_certificate_set_x509_simple_pkcs12_file
  (gnutls_certificate_credentials_t res, char *pkcs12file,
   gnutls_x509_crt_fmt_t type, char *password);
  int gnutls_certificate_set_x509_simple_pkcs12_mem
  (gnutls_certificate_credentials_t res, gnutls_datum_t *p12blob,
   gnutls_x509_crt_fmt_t type, char *password);

/* New functions to allow setting already parsed X.509 stuff.
 */
  alias gnutls_x509_privkey_int *gnutls_x509_privkey_t;

  struct gnutls_x509_crl_int;
  alias gnutls_x509_crl_int *gnutls_x509_crl_t;

  struct gnutls_x509_crt_int;
  alias gnutls_x509_crt_int *gnutls_x509_crt_t;

  struct gnutls_openpgp_keyring_int;
  alias gnutls_openpgp_keyring_int *gnutls_openpgp_keyring_t;

  int gnutls_certificate_set_x509_key (gnutls_certificate_credentials_t res,
				       gnutls_x509_crt_t * cert_list,
				       int cert_list_size,
				       gnutls_x509_privkey_t key);
  int gnutls_certificate_set_x509_trust (gnutls_certificate_credentials_t res,
					 gnutls_x509_crt_t * ca_list,
					 int ca_list_size);
  int gnutls_certificate_set_x509_crl (gnutls_certificate_credentials_t res,
				       gnutls_x509_crl_t * crl_list,
				       int crl_list_size);

  void gnutls_certificate_get_x509_cas (gnutls_certificate_credentials_t sc,
					gnutls_x509_crt_t **x509_ca_list,
					uint* ncas);

  void gnutls_certificate_get_x509_crls (gnutls_certificate_credentials_t sc,
					 gnutls_x509_crl_t **x509_crl_list,
					 uint* ncrls);

  void gnutls_certificate_get_openpgp_keyring (gnutls_certificate_credentials_t sc,
					       gnutls_openpgp_keyring_t *keyring);

/* global state functions
 */
  int gnutls_global_init ();
  void gnutls_global_deinit ();

  alias void *(*gnutls_alloc_function) (size_t);
  alias void *(*gnutls_calloc_function) (size_t, size_t);
  alias int (*gnutls_is_secure_function) (void *);
  alias void (*gnutls_free_function) (void *);
  alias void *(*gnutls_realloc_function) (void *, size_t);

  void
  gnutls_global_set_mem_functions (gnutls_alloc_function alloc_func,
				   gnutls_alloc_function secure_alloc_func,
				   gnutls_is_secure_function is_secure_func,
				   gnutls_realloc_function realloc_func,
				   gnutls_free_function free_func);

/* For use in callbacks */
  extern gnutls_alloc_function gnutls_malloc;
  extern gnutls_alloc_function gnutls_secure_malloc;
  extern gnutls_realloc_function gnutls_realloc;
  extern gnutls_calloc_function gnutls_calloc;
  extern gnutls_free_function gnutls_free;

  extern char *(*gnutls_strdup) (char *);

  alias void (*gnutls_log_func) (int, char *);
  void gnutls_global_set_log_function (gnutls_log_func log_func);
  void gnutls_global_set_log_level (int level);

/* Diffie-Hellman parameter handling.
 */
  int gnutls_dh_params_init (gnutls_dh_params_t * dh_params);
  void gnutls_dh_params_deinit (gnutls_dh_params_t dh_params);
  int gnutls_dh_params_import_raw (gnutls_dh_params_t dh_params,
				   gnutls_datum_t * prime,
				   gnutls_datum_t * generator);
  int gnutls_dh_params_import_pkcs3 (gnutls_dh_params_t params,
				     gnutls_datum_t * pkcs3_params,
				     gnutls_x509_crt_fmt_t format);
  int gnutls_dh_params_generate2 (gnutls_dh_params_t params,
				  uint bits);
  int gnutls_dh_params_export_pkcs3 (gnutls_dh_params_t params,
				     gnutls_x509_crt_fmt_t format,
				     char *params_data,
				     size_t * params_data_size);
  int gnutls_dh_params_export_raw (gnutls_dh_params_t params,
				   gnutls_datum_t * prime,
				   gnutls_datum_t * generator,
				   uint *bits);
  int gnutls_dh_params_cpy (gnutls_dh_params_t dst, gnutls_dh_params_t src);


/* RSA params 
 */
  int gnutls_rsa_params_init (gnutls_rsa_params_t * rsa_params);
  void gnutls_rsa_params_deinit (gnutls_rsa_params_t rsa_params);
  int gnutls_rsa_params_cpy (gnutls_rsa_params_t dst,
			     gnutls_rsa_params_t src);
  int gnutls_rsa_params_import_raw (gnutls_rsa_params_t rsa_params,
				    gnutls_datum_t * m,
				    gnutls_datum_t * e,
				    gnutls_datum_t * d,
				    gnutls_datum_t * p,
				    gnutls_datum_t * q,
				    gnutls_datum_t * u);
  int gnutls_rsa_params_generate2 (gnutls_rsa_params_t params,
				   uint bits);
  int gnutls_rsa_params_export_raw (gnutls_rsa_params_t params,
				    gnutls_datum_t * m, gnutls_datum_t * e,
				    gnutls_datum_t * d, gnutls_datum_t * p,
				    gnutls_datum_t * q, gnutls_datum_t * u,
				    uint *bits);
  int gnutls_rsa_params_export_pkcs1 (gnutls_rsa_params_t params,
				      gnutls_x509_crt_fmt_t format,
				      char *params_data,
				      size_t * params_data_size);
  int gnutls_rsa_params_import_pkcs1 (gnutls_rsa_params_t params,
				      gnutls_datum_t * pkcs1_params,
				      gnutls_x509_crt_fmt_t format);

/* Session stuff
 */
  alias ssize_t (*gnutls_pull_func) (gnutls_transport_ptr_t, void *,
				       size_t);
  alias ssize_t (*gnutls_push_func) (gnutls_transport_ptr_t, void *,
				       size_t);
  void gnutls_transport_set_ptr (gnutls_session_t session,
				 gnutls_transport_ptr_t ptr);
  void gnutls_transport_set_ptr2 (gnutls_session_t session,
				  gnutls_transport_ptr_t recv_ptr,
				  gnutls_transport_ptr_t send_ptr);

  gnutls_transport_ptr_t gnutls_transport_get_ptr (gnutls_session_t session);
  void gnutls_transport_get_ptr2 (gnutls_session_t session,
				  gnutls_transport_ptr_t * recv_ptr,
				  gnutls_transport_ptr_t * send_ptr);

  void gnutls_transport_set_lowat (gnutls_session_t session, int num);


  void gnutls_transport_set_push_function (gnutls_session_t session,
					   gnutls_push_func push_func);
  void gnutls_transport_set_pull_function (gnutls_session_t session,
					   gnutls_pull_func pull_func);

  void gnutls_transport_set_errno (gnutls_session_t session, int err);
  void gnutls_transport_set_global_errno (int err);

/* session specific 
 */
  void gnutls_session_set_ptr (gnutls_session_t session, void *ptr);
  void *gnutls_session_get_ptr (gnutls_session_t session);

  void gnutls_openpgp_send_cert (gnutls_session_t session,
				gnutls_openpgp_crt_status_t status);

/* fingerprint 
 * Actually this function returns the hash of the given data.
 */
  int gnutls_fingerprint (gnutls_digest_algorithm_t algo,
			  gnutls_datum_t * data, void *result,
			  size_t * result_size);


/* SRP 
 */

  struct gnutls_srp_server_credentials_st;
  alias gnutls_srp_server_credentials_st
    *gnutls_srp_server_credentials_t;
  struct gnutls_srp_client_credentials_st;
  alias gnutls_srp_client_credentials_st
    *gnutls_srp_client_credentials_t;

  void
  gnutls_srp_free_client_credentials (gnutls_srp_client_credentials_t sc);
  int
  gnutls_srp_allocate_client_credentials (gnutls_srp_client_credentials_t * sc);
  int
  gnutls_srp_set_client_credentials (gnutls_srp_client_credentials_t res,
				     char *username,
				     char *password);

  void
  gnutls_srp_free_server_credentials (gnutls_srp_server_credentials_t sc);
  int
  gnutls_srp_allocate_server_credentials (gnutls_srp_server_credentials_t *sc);
  int
  gnutls_srp_set_server_credentials_file (gnutls_srp_server_credentials_t res,
					  char *password_file,
					  char *password_conf_file);

  char *gnutls_srp_server_get_username (gnutls_session_t session);

  extern void gnutls_srp_set_prime_bits (gnutls_session_t session,
					 uint bits);

  int gnutls_srp_verifier (char *username,
			   char *password,
			   gnutls_datum_t * salt,
			   gnutls_datum_t * generator,
			   gnutls_datum_t * prime,
			   gnutls_datum_t * res);

/* The static parameters defined in draft-ietf-tls-srp-05
 * Those should be used as input to gnutls_srp_verifier().
 */
  extern const gnutls_datum_t gnutls_srp_2048_group_prime;
  extern const gnutls_datum_t gnutls_srp_2048_group_generator;

  extern const gnutls_datum_t gnutls_srp_1536_group_prime;
  extern const gnutls_datum_t gnutls_srp_1536_group_generator;

  extern const gnutls_datum_t gnutls_srp_1024_group_prime;
  extern const gnutls_datum_t gnutls_srp_1024_group_generator;

  alias int gnutls_srp_server_credentials_function (gnutls_session_t,
						      char *username,
						      gnutls_datum_t * salt,
						      gnutls_datum_t *
						      verifier,
						      gnutls_datum_t *
						      generator,
						      gnutls_datum_t * prime);
  void
    gnutls_srp_set_server_credentials_function
    (gnutls_srp_server_credentials_t cred,
     gnutls_srp_server_credentials_function * func);

  alias int gnutls_srp_client_credentials_function (gnutls_session_t,
						      char **, char **);
  void
    gnutls_srp_set_client_credentials_function
    (gnutls_srp_client_credentials_t cred,
     gnutls_srp_client_credentials_function * func);

  int gnutls_srp_base64_encode (gnutls_datum_t * data, char *result,
				size_t * result_size);
  int gnutls_srp_base64_encode_alloc (gnutls_datum_t * data,
				      gnutls_datum_t * result);

  int gnutls_srp_base64_decode (gnutls_datum_t * b64_data, char *result,
				size_t * result_size);
  int gnutls_srp_base64_decode_alloc (gnutls_datum_t * b64_data,
				      gnutls_datum_t * result);

/* PSK stuff */
  struct gnutls_psk_server_credentials_st;
  alias gnutls_psk_server_credentials_st
    *gnutls_psk_server_credentials_t;
  struct gnutls_psk_client_credentials_st;
  alias gnutls_psk_client_credentials_st
    *gnutls_psk_client_credentials_t;

  enum gnutls_psk_key_flags
    {
      GNUTLS_PSK_KEY_RAW = 0,
      GNUTLS_PSK_KEY_HEX
    };

  void
  gnutls_psk_free_client_credentials (gnutls_psk_client_credentials_t sc);
  int
  gnutls_psk_allocate_client_credentials (gnutls_psk_client_credentials_t * sc);
  int gnutls_psk_set_client_credentials (gnutls_psk_client_credentials_t res,
					 char *username,
					 gnutls_datum_t * key,
					 gnutls_psk_key_flags format);

  void
  gnutls_psk_free_server_credentials (gnutls_psk_server_credentials_t sc);
  int
  gnutls_psk_allocate_server_credentials (gnutls_psk_server_credentials_t * sc);
  int
  gnutls_psk_set_server_credentials_file (gnutls_psk_server_credentials_t res,
					  char *password_file);

  int
  gnutls_psk_set_server_credentials_hint (gnutls_psk_server_credentials_t res,
					  char *hint);

  char *gnutls_psk_server_get_username (gnutls_session_t session);
  char *gnutls_psk_client_get_hint (gnutls_session_t session);

  alias int gnutls_psk_server_credentials_function (gnutls_session_t,
						      char *username,
						      gnutls_datum_t * key);
  void
  gnutls_psk_set_server_credentials_function
  (gnutls_psk_server_credentials_t cred,
   gnutls_psk_server_credentials_function * func);

  alias int gnutls_psk_client_credentials_function (gnutls_session_t,
						      char **username,
						      gnutls_datum_t * key);
  void
    gnutls_psk_set_client_credentials_function
    (gnutls_psk_client_credentials_t cred,
     gnutls_psk_client_credentials_function * func);

  int gnutls_hex_encode (gnutls_datum_t * data, char *result,
			 size_t * result_size);
  int gnutls_hex_decode (gnutls_datum_t * hex_data, char *result,
			 size_t * result_size);

  void
  gnutls_psk_set_server_dh_params (gnutls_psk_server_credentials_t res,
				   gnutls_dh_params_t dh_params);

  void
  gnutls_psk_set_server_params_function (gnutls_psk_server_credentials_t res,
					 gnutls_params_function * func);

  int gnutls_psk_netconf_derive_key (char *password,
				     char *psk_identity,
				     char *psk_identity_hint,
				     gnutls_datum_t *output_key);


  enum gnutls_x509_subject_alt_name_t
  {
    GNUTLS_SAN_DNSNAME = 1,
    GNUTLS_SAN_RFC822NAME,
    GNUTLS_SAN_URI,
    GNUTLS_SAN_IPADDRESS,
    GNUTLS_SAN_OTHERNAME,
    GNUTLS_SAN_DN,
    /* The following are "virtual" subject alternative name types, in
       that they are represented by an otherName value and an OID.
       Used by gnutls_x509_crt_get_subject_alt_othername_oid().  */
    GNUTLS_SAN_OTHERNAME_XMPP = 1000
  };

  struct gnutls_openpgp_crt_int;
  alias gnutls_openpgp_crt_int *gnutls_openpgp_crt_t;

  struct gnutls_openpgp_privkey_int;
  alias gnutls_openpgp_privkey_int *gnutls_openpgp_privkey_t;

  struct gnutls_retr_st
  {
    gnutls_certificate_type_t type;
    union cert
    {
      gnutls_x509_crt_t *x509;
      gnutls_openpgp_crt_t pgp;
    };
    uint ncerts;	/* one for pgp keys */

    union key
    {
      gnutls_x509_privkey_t x509;
      gnutls_openpgp_privkey_t pgp;
    };

    uint deinit_all;	/* if non zero all keys will be deinited */
  };

  alias int gnutls_certificate_client_retrieve_function (gnutls_session_t,
							   gnutls_datum_t *
							   req_ca_rdn,
							   int nreqs,
							   gnutls_pk_algorithm_t
							   * pk_algos,
							   int
							   pk_algos_length,
							   gnutls_retr_st *);
  alias int gnutls_certificate_server_retrieve_function (gnutls_session_t,
							   gnutls_retr_st *);


  /* Functions that allow auth_info_t structures handling
   */

  gnutls_credentials_type_t gnutls_auth_get_type (gnutls_session_t session);
    gnutls_credentials_type_t
    gnutls_auth_server_get_type (gnutls_session_t session);
    gnutls_credentials_type_t
    gnutls_auth_client_get_type (gnutls_session_t session);

  /* DH */

  void gnutls_dh_set_prime_bits (gnutls_session_t session, uint bits);
  int gnutls_dh_get_secret_bits (gnutls_session_t session);
  int gnutls_dh_get_peers_public_bits (gnutls_session_t session);
  int gnutls_dh_get_prime_bits (gnutls_session_t session);

  int gnutls_dh_get_group (gnutls_session_t session, gnutls_datum_t * raw_gen,
			   gnutls_datum_t * raw_prime);
  int gnutls_dh_get_pubkey (gnutls_session_t session,
			    gnutls_datum_t * raw_key);

  /* RSA */
  int gnutls_rsa_export_get_pubkey (gnutls_session_t session,
				    gnutls_datum_t * exponent,
				    gnutls_datum_t * modulus);
  int gnutls_rsa_export_get_modulus_bits (gnutls_session_t session);

  /* X509PKI */

  /* External signing callback.  Experimental. */
  alias int (*gnutls_sign_func) (gnutls_session_t session,
				   void *userdata,
				   gnutls_certificate_type_t cert_type,
				   gnutls_datum_t * cert,
				   gnutls_datum_t * hash,
				   gnutls_datum_t * signature);

  void gnutls_sign_callback_set (gnutls_session_t session,
				 gnutls_sign_func sign_func,
				 void *userdata);
  gnutls_sign_func
  gnutls_sign_callback_get (gnutls_session_t session,
			    void **userdata);

  /* These are set on the credentials structure.
   */
  void gnutls_certificate_client_set_retrieve_function
    (gnutls_certificate_credentials_t cred,
     gnutls_certificate_client_retrieve_function * func);
  void gnutls_certificate_server_set_retrieve_function
    (gnutls_certificate_credentials_t cred,
     gnutls_certificate_server_retrieve_function * func);

  void
  gnutls_certificate_server_set_request (gnutls_session_t session,
					 gnutls_certificate_request_t req);

  /* get data from the session
   */
  gnutls_datum_t *
  gnutls_certificate_get_peers (gnutls_session_t session,
				uint *list_size);
  gnutls_datum_t *
  gnutls_certificate_get_ours (gnutls_session_t session);

  time_t gnutls_certificate_activation_time_peers (gnutls_session_t session);
  time_t gnutls_certificate_expiration_time_peers (gnutls_session_t session);

  int gnutls_certificate_client_get_request_status (gnutls_session_t session);
  int gnutls_certificate_verify_peers2 (gnutls_session_t session,
					uint *status);

  /* this is obsolete (?). */
  int gnutls_certificate_verify_peers (gnutls_session_t session);

  int gnutls_pem_base64_encode (char *msg, gnutls_datum_t * data,
				char *result, size_t * result_size);
  int gnutls_pem_base64_decode (char *header,
				gnutls_datum_t * b64_data,
				char *result, size_t * result_size);

  int gnutls_pem_base64_encode_alloc (char *msg,
				      gnutls_datum_t * data,
				      gnutls_datum_t * result);
  int gnutls_pem_base64_decode_alloc (char *header,
				      gnutls_datum_t * b64_data,
				      gnutls_datum_t * result);

  /* key_usage will be an OR of the following values:
   */

  /* when the key is to be used for signing: */
const int GNUTLS_KEY_DIGITAL_SIGNATURE = 128;
const int GNUTLS_KEY_NON_REPUDIATION = 64;
  /* when the key is to be used for encryption: */
const int GNUTLS_KEY_KEY_ENCIPHERMENT = 32;
const int GNUTLS_KEY_DATA_ENCIPHERMENT = 16;
const int GNUTLS_KEY_KEY_AGREEMENT = 8;
const int GNUTLS_KEY_KEY_CERT_SIGN = 4;
const int GNUTLS_KEY_CRL_SIGN = 2;
const int GNUTLS_KEY_ENCIPHER_ONLY = 1;
const int GNUTLS_KEY_DECIPHER_ONLY = 32768;

  void
  gnutls_certificate_set_params_function (gnutls_certificate_credentials_t res,
					  gnutls_params_function * func);
  void gnutls_anon_set_params_function (gnutls_anon_server_credentials_t res,
					gnutls_params_function * func);
  void gnutls_psk_set_params_function (gnutls_psk_server_credentials_t res,
				       gnutls_params_function * func);

  int gnutls_hex2bin (char * hex_data, size_t hex_size,
		      char * bin_data, size_t * bin_size);

  /* Gnutls error codes. The mapping to a TLS alert is also shown in
   * comments.
   */

const int GNUTLS_E_SUCCESS = 0;
const int GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM = -3;
const int GNUTLS_E_UNKNOWN_CIPHER_TYPE = -6;
const int GNUTLS_E_LARGE_PACKET = -7;
const int GNUTLS_E_UNSUPPORTED_VERSION_PACKET = -8;	/* GNUTLS_A_PROTOCOL_VERSION */
const int GNUTLS_E_UNEXPECTED_PACKET_LENGTH = -9;	/* GNUTLS_A_RECORD_OVERFLOW */
const int GNUTLS_E_INVALID_SESSION = -10;
const int GNUTLS_E_FATAL_ALERT_RECEIVED = -12;
const int GNUTLS_E_UNEXPECTED_PACKET = -15;	/* GNUTLS_A_UNEXPECTED_MESSAGE */
const int GNUTLS_E_WARNING_ALERT_RECEIVED = -16;
const int GNUTLS_E_ERROR_IN_FINISHED_PACKET = -18;
const int GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET = -19;
const int GNUTLS_E_UNKNOWN_CIPHER_SUITE = -21;	/* GNUTLS_A_HANDSHAKE_FAILURE */
const int GNUTLS_E_UNWANTED_ALGORITHM = -22;
const int GNUTLS_E_MPI_SCAN_FAILED = -23;
const int GNUTLS_E_DECRYPTION_FAILED = -24;	/* GNUTLS_A_DECRYPTION_FAILED, GNUTLS_A_BAD_RECORD_MAC */
const int GNUTLS_E_MEMORY_ERROR = -25;
const int GNUTLS_E_DECOMPRESSION_FAILED = -26;	/* GNUTLS_A_DECOMPRESSION_FAILURE */
const int GNUTLS_E_COMPRESSION_FAILED = -27;
const int GNUTLS_E_AGAIN = -28;
const int GNUTLS_E_EXPIRED = -29;
const int GNUTLS_E_DB_ERROR = -30;
const int GNUTLS_E_SRP_PWD_ERROR = -31;
const int GNUTLS_E_INSUFFICIENT_CREDENTIALS = -32;
alias GNUTLS_E_INSUFFICIENT_CREDENTIALS GNUTLS_E_INSUFICIENT_CREDENTIALS;	/* for backwards compatibility only */
alias GNUTLS_E_INSUFFICIENT_CREDENTIALS GNUTLS_E_INSUFFICIENT_CRED;
alias GNUTLS_E_INSUFFICIENT_CREDENTIALS GNUTLS_E_INSUFICIENT_CRED;	/* for backwards compatibility only */
const int GNUTLS_E_HASH_FAILED = -33;
const int GNUTLS_E_BASE64_DECODING_ERROR = -34;

const int GNUTLS_E_MPI_PRINT_FAILED = -35;
const int GNUTLS_E_REHANDSHAKE = -37;	/* GNUTLS_A_NO_RENEGOTIATION */
const int GNUTLS_E_GOT_APPLICATION_DATA = -38;
const int GNUTLS_E_RECORD_LIMIT_REACHED = -39;
const int GNUTLS_E_ENCRYPTION_FAILED = -40;
const int GNUTLS_E_PK_ENCRYPTION_FAILED = -44;
const int GNUTLS_E_PK_DECRYPTION_FAILED = -45;
const int GNUTLS_E_PK_SIGN_FAILED = -46;
const int GNUTLS_E_X509_UNSUPPORTED_CRITICAL_EXTENSION = -47;
const int GNUTLS_E_KEY_USAGE_VIOLATION = -48;
const int GNUTLS_E_NO_CERTIFICATE_FOUND = -49;	/* GNUTLS_A_BAD_CERTIFICATE */
const int GNUTLS_E_INVALID_REQUEST = -50;
const int GNUTLS_E_SHORT_MEMORY_BUFFER = -51;
const int GNUTLS_E_INTERRUPTED = -52;
const int GNUTLS_E_PUSH_ERROR = -53;
const int GNUTLS_E_PULL_ERROR = -54;
const int GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER = -55;	/* GNUTLS_A_ILLEGAL_PARAMETER */
const int GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE = -56;
const int GNUTLS_E_PKCS1_WRONG_PAD = -57;
const int GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION = -58;
const int GNUTLS_E_INTERNAL_ERROR = -59;
const int GNUTLS_E_DH_PRIME_UNACCEPTABLE = -63;
const int GNUTLS_E_FILE_ERROR = -64;
const int GNUTLS_E_TOO_MANY_EMPTY_PACKETS = -78;
const int GNUTLS_E_UNKNOWN_PK_ALGORITHM = -80;


  /* returned if libextra functionality was requested but
   * gnutls_global_init_extra() was not called.
   */
const int GNUTLS_E_INIT_LIBEXTRA = -82;
const int GNUTLS_E_LIBRARY_VERSION_MISMATCH = -83;


  /* returned if you need to generate temporary RSA
   * parameters. These are needed for export cipher suites.
   */
const int GNUTLS_E_NO_TEMPORARY_RSA_PARAMS = -84;
const int GNUTLS_E_LZO_INIT_FAILED = -85;
const int GNUTLS_E_NO_COMPRESSION_ALGORITHMS = -86;
const int GNUTLS_E_NO_CIPHER_SUITES = -87;
const int GNUTLS_E_OPENPGP_GETKEY_FAILED = -88;
const int GNUTLS_E_PK_SIG_VERIFY_FAILED = -89;
const int GNUTLS_E_ILLEGAL_SRP_USERNAME = -90;
const int GNUTLS_E_SRP_PWD_PARSING_ERROR = -91;
const int GNUTLS_E_NO_TEMPORARY_DH_PARAMS = -93;

  /* For certificate and key stuff
   */
const int GNUTLS_E_ASN1_ELEMENT_NOT_FOUND = -67;
const int GNUTLS_E_ASN1_IDENTIFIER_NOT_FOUND = -68;
const int GNUTLS_E_ASN1_DER_ERROR = -69;
const int GNUTLS_E_ASN1_VALUE_NOT_FOUND = -70;
const int GNUTLS_E_ASN1_GENERIC_ERROR = -71;
const int GNUTLS_E_ASN1_VALUE_NOT_VALID = -72;
const int GNUTLS_E_ASN1_TAG_ERROR = -73;
const int GNUTLS_E_ASN1_TAG_IMPLICIT = -74;
const int GNUTLS_E_ASN1_TYPE_ANY_ERROR = -75;
const int GNUTLS_E_ASN1_SYNTAX_ERROR = -76;
const int GNUTLS_E_ASN1_DER_OVERFLOW = -77;
const int GNUTLS_E_OPENPGP_UID_REVOKED = -79;
const int GNUTLS_E_CERTIFICATE_ERROR = -43;
alias GNUTLS_E_CERTIFICATE_ERROR GNUTLS_E_X509_CERTIFICATE_ERROR;
const int GNUTLS_E_CERTIFICATE_KEY_MISMATCH = -60;
const int GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE = -61;	/* GNUTLS_A_UNSUPPORTED_CERTIFICATE */
const int GNUTLS_E_X509_UNKNOWN_SAN = -62;
const int GNUTLS_E_OPENPGP_FINGERPRINT_UNSUPPORTED = -94;
const int GNUTLS_E_X509_UNSUPPORTED_ATTRIBUTE = -95;
const int GNUTLS_E_UNKNOWN_HASH_ALGORITHM = -96;
const int GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE = -97;
const int GNUTLS_E_UNKNOWN_PKCS_BAG_TYPE = -98;
const int GNUTLS_E_INVALID_PASSWORD = -99;
const int GNUTLS_E_MAC_VERIFY_FAILED = -100;	/* for PKCS #12 MAC */
const int GNUTLS_E_CONSTRAINT_ERROR = -101;
const int GNUTLS_E_WARNING_IA_IPHF_RECEIVED = -102;
const int GNUTLS_E_WARNING_IA_FPHF_RECEIVED = -103;
const int GNUTLS_E_IA_VERIFY_FAILED = -104;
const int GNUTLS_E_UNKNOWN_ALGORITHM = -105;
const int GNUTLS_E_BASE64_ENCODING_ERROR = -201;
const int GNUTLS_E_INCOMPATIBLE_GCRYPT_LIBRARY = -202;	/* obsolete */
const int GNUTLS_E_INCOMPATIBLE_CRYPTO_LIBRARY = -202;
const int GNUTLS_E_INCOMPATIBLE_LIBTASN1_LIBRARY = -203;
const int GNUTLS_E_OPENPGP_KEYRING_ERROR = -204;
const int GNUTLS_E_X509_UNSUPPORTED_OID = -205;
const int GNUTLS_E_RANDOM_FAILED = -206;
const int GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR = -207;
const int GNUTLS_E_OPENPGP_SUBKEY_ERROR = -208;
const int GNUTLS_E_CRYPTO_ALREADY_REGISTERED = -209;
const int GNUTLS_E_HANDSHAKE_TOO_LARGE = -210;
const int GNUTLS_E_UNIMPLEMENTED_FEATURE = -1250;
const int GNUTLS_E_APPLICATION_ERROR_MAX = -65000;
const int GNUTLS_E_APPLICATION_ERROR_MIN = -65500;

/* Typedefs for more compatibility with older GnuTLS. */


alias gnutls_cipher_algorithm gnutls_cipher_algorithm_t;
alias gnutls_kx_algorithm_t gnutls_kx_algorithm;
alias gnutls_params_type_t gnutls_params_type;
alias gnutls_mac_algorithm_t gnutls_mac_algorithm;
alias gnutls_digest_algorithm_t gnutls_digest_algorithm;
alias gnutls_compression_method_t gnutls_compression_method;
alias gnutls_connection_end_t gnutls_connection_end;
alias gnutls_credentials_type_t gnutls_credentials_type;
alias gnutls_certificate_type_t gnutls_certificate_type;
alias gnutls_x509_crt_fmt_t gnutls_x509_crt_fmt;
//alias gnutls_openpgp_key_fmt_t gnutls_openpgp_key_fmt;
alias gnutls_pk_algorithm_t gnutls_pk_algorithm;
alias gnutls_sign_algorithm_t gnutls_sign_algorithm;
alias gnutls_server_name_type_t gnutls_server_name;
//alias gnutls_protocol_version_t gnutls_protocol;
alias gnutls_close_request_t gnutls_close_request;
//alias gnutls_openpgp_key_status_t gnutls_openpgp_key_status;
alias gnutls_certificate_request_t gnutls_certificate_request;
alias gnutls_certificate_status_t gnutls_certificate_status;
alias gnutls_session_t gnutls_session;
alias gnutls_alert_level_t gnutls_alert_level;
alias gnutls_alert_description_t gnutls_alert_description;
alias gnutls_x509_subject_alt_name_t gnutls_x509_subject_alt_name;
//alias gnutls_openpgp_key_t gnutls_openpgp_key;
alias gnutls_openpgp_privkey_t gnutls_openpgp_privkey;
alias gnutls_openpgp_keyring_t gnutls_openpgp_keyring;
alias gnutls_x509_crt_t gnutls_x509_crt;
alias gnutls_x509_privkey_t gnutls_x509_privkey;
alias gnutls_x509_crl_t gnutls_x509_crl;
//alias gnutls_pkcs7_t gnutls_pkcs7;
//alias gnutls_x509_crq_t gnutls_x509_crq;
//alias gnutls_pkcs_encrypt_flags_t gnutls_pkcs_encrypt_flags;
//alias gnutls_pkcs12_bag_type_t gnutls_pkcs12_bag_type;
//alias gnutls_pkcs12_bag_t gnutls_pkcs12_bag;
//alias gnutls_pkcs12_t gnutls_pkcs12;
alias gnutls_certificate_credentials_t gnutls_certificate_credentials;
alias gnutls_anon_server_credentials_t gnutls_anon_server_credentials;
alias gnutls_anon_client_credentials_t gnutls_anon_client_credentials;
alias gnutls_srp_client_credentials_t gnutls_srp_client_credentials;
alias gnutls_srp_server_credentials_t gnutls_srp_server_credentials;
alias gnutls_dh_params_t gnutls_dh_params;
alias gnutls_rsa_params_t gnutls_rsa_params;
alias gnutls_datum_t gnutls_datum;
alias gnutls_transport_ptr_t gnutls_transport_ptr;

/* Old SRP alerts removed in 2.1.x because the TLS-SRP RFC was
   modified to use the PSK alert. */
alias GNUTLS_A_UNKNOWN_PSK_IDENTITY GNUTLS_A_MISSING_SRP_USERNAME;
alias GNUTLS_A_UNKNOWN_PSK_IDENTITY GNUTLS_A_UNKNOWN_SRP_USERNAME;

/* OpenPGP stuff renamed in 2.1.x. */
//alias gnutls_openpgp_key_fmt_t gnutls_openpgp_crt_fmt_t;
alias GNUTLS_OPENPGP_CERT GNUTLS_OPENPGP_KEY;
alias GNUTLS_OPENPGP_CERT_FINGERPRINT GNUTLS_OPENPGP_KEY_FINGERPRINT;
alias gnutls_openpgp_send_cert gnutls_openpgp_send_key;
alias gnutls_openpgp_crt_status_t gnutls_openpgp_key_status_t;
alias gnutls_openpgp_crt_t gnutls_openpgp_key_t;
//alias gnutls_openpgp_crt_init gnutls_openpgp_key_init;
//alias gnutls_openpgp_crt_deinit gnutls_openpgp_key_deinit;
//alias gnutls_openpgp_crt_import gnutls_openpgp_key_import;
//alias gnutls_openpgp_crt_export gnutls_openpgp_key_export;
//alias gnutls_openpgp_crt_get_key_usage gnutls_openpgp_key_get_key_usage;
//alias gnutls_openpgp_crt_get_fingerprint gnutls_openpgp_key_get_fingerprint;
//alias gnutls_openpgp_crt_get_pk_algorithm gnutls_openpgp_key_get_pk_algorithm;
//alias gnutls_openpgp_crt_get_name gnutls_openpgp_key_get_name;
//alias gnutls_openpgp_crt_get_version gnutls_openpgp_key_get_version;
//alias gnutls_openpgp_crt_get_creation_time gnutls_openpgp_key_get_creation_time;
//alias gnutls_openpgp_crt_get_expiration_time gnutls_openpgp_key_get_expiration_time;
//alias gnutls_openpgp_crt_get_id gnutls_openpgp_key_get_id;
//alias gnutls_openpgp_crt_check_hostname gnutls_openpgp_key_check_hostname;

/* OpenPGP stuff renamed in 2.3.x. */
//alias gnutls_openpgp_crt_get_key_id gnutls_openpgp_crt_get_id;

/* New better names renamed in 2.3.x, add these for backwards
   compatibility with old poor names.*/
alias GNUTLS_CRT_PRINT_FULL GNUTLS_X509_CRT_FULL;
alias GNUTLS_CRT_PRINT_ONELINE GNUTLS_X509_CRT_ONELINE;
alias GNUTLS_CRT_PRINT_UNSIGNED_FULL GNUTLS_X509_CRT_UNSIGNED_FULL;

/* These old alias's violate the gnutls_* namespace. */
alias GNUTLS_MASTER_SIZE TLS_MASTER_SIZE;
alias GNUTLS_RANDOM_SIZE TLS_RANDOM_SIZE;

/* Namespace problems. */
alias GNUTLS_VERSION LIBGNUTLS_VERSION;
alias GNUTLS_VERSION_MAJOR LIBGNUTLS_VERSION_MAJOR;
alias GNUTLS_VERSION_MINOR LIBGNUTLS_VERSION_MINOR;
alias GNUTLS_VERSION_PATCH LIBGNUTLS_VERSION_PATCH;
alias GNUTLS_VERSION_NUMBER LIBGNUTLS_VERSION_NUMBER;
alias GNUTLS_VERSION LIBGNUTLS_EXTRA_VERSION;
}
