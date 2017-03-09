/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifndef CURL_DISABLE_NFS

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_UTSNAME_H
#include <sys/utsname.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#if (defined(NETWARE) && defined(__NOVELL_LIBC__))
#undef in_addr_t
#define in_addr_t unsigned long
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "if2ip.h"
#include "hostip.h"
#include "progress.h"
#include "transfer.h"
#include "escape.h"
#include "http.h" /* for HTTP proxy tunnel stuff */
#include "socks.h"
#include "ftp.h"
#include "fileinfo.h"
#include "ftplistparser.h"
#include "curl_sec.h"
#include "strtoofft.h"
#include "strcase.h"
#include "vtls/vtls.h"
#include "connect.h"
#include "strerror.h"
#include "inet_ntop.h"
#include "inet_pton.h"
#include "select.h"
#include "parsedate.h" /* for the week day and month names */
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "multiif.h"
#include "url.h"
#include "strcase.h"
#include "speedcheck.h"
#include "warnless.h"
#include "http_proxy.h"
#include "non-ascii.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif
#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

static CURLcode nfs_connect(struct connectdata *conn, bool *done);
static CURLcode nfs_setup_connection(struct connectdata * conn);


/*
 * NFS protocol handler.
 */

const struct Curl_handler Curl_handler_nfs = {
  "NFS",                           /* scheme */
  nfs_setup_connection,            /* setup_connection */
  ZERO_NULL,                       /* do_it */
  ZERO_NULL,                       /* done */
  ZERO_NULL,                       /* do_more */
  nfs_connect,                     /* connect_it */
  ZERO_NULL,                       /* connecting */
  ZERO_NULL,                       /* doing */
  ZERO_NULL,                       /* proto_getsock */
  ZERO_NULL,                       /* doing_getsock */
  ZERO_NULL,                       /* domore_getsock */
  ZERO_NULL,                       /* perform_getsock */
  ZERO_NULL,                       /* disconnect */
  ZERO_NULL,                       /* readwrite */
  PORT_NFS,                        /* defport */
  CURLPROTO_NFS,                   /* protocol */
  PROTOPT_DUAL | PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY /* flags */
};


/*
 * nfs_connect() should do everything that is to be considered a part of
 * the connection phase.
 *
 * The variable 'done' points to will be TRUE if the protocol-layer connect
 * phase is done when this function returns, or FALSE if not.
 *
 */
static CURLcode nfs_connect(struct connectdata *conn,
                                 bool *done) /* see description above */
{
  CURLcode result;
  struct nfs_conn *nfsc = &conn->proto.nfsc;

  *done = FALSE; /* default to not done yet */

  /* We always support persistent connections on NFS */
  connkeep(conn, "NFS default");

  return result;
}

static CURLcode nfs_setup_connection(struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;
  char *type;
  char command;
  struct FTP *ftp;

  conn->data->req.protop = ftp = malloc(sizeof(struct FTP));
  if(NULL == ftp)
    return CURLE_OUT_OF_MEMORY;

  /* get some initial data into the ftp struct */
  ftp->bytecountp = &conn->data->req.bytecount;
  ftp->transfer = FTPTRANSFER_BODY;
  ftp->downloadsize = 0;

  return CURLE_OK;
}

#endif /* CURL_DISABLE_NFS */
