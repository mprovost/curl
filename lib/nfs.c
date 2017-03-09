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
static char *nfs_fh3_to_string(nfs_fh3);
static CURLcode nfs_do(struct connectdata *conn, bool *done);
static int nfs_bindresvport(void *, curl_socket_t, curlsocktype);
static CURLcode nfs_setup_connection(struct connectdata * conn);


/*
 * NFS protocol handler.
 */

const struct Curl_handler Curl_handler_nfs = {
  "NFS",                           /* scheme */
  nfs_setup_connection,            /* setup_connection */
  nfs_do,                          /* do_it */
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
  CURLcode result = CURLE_COULDNT_CONNECT;
  struct nfs_conn *nfsc = &conn->proto.nfsc;
  struct sockaddr_in sai;
  struct sockaddr_in getaddr; /* for getsockname */
  curl_socklen_t size = (curl_socklen_t) sizeof(sai);
  *done = FALSE; /* default to not done yet */
  int sock = conn->sock[FIRSTSOCKET];
  void *status = NULL;

  if(0 == getsockname(
    conn->sock[FIRSTSOCKET], (struct sockaddr *) &sai, &size)) {
    size = sizeof(sai);
  }

  /* We always support persistent connections on NFS */
  connkeep(conn, "NFS default");

  /* connect to NFS */
  nfsc->nfs_client = clnttcp_create(
    &sai, NFS3_PROGRAM, 3, &sock, 0, 0);

  if(nfsc->nfs_client == NULL) {
    result = CURLE_COULDNT_CONNECT;
  }

  /* ping */
  status = nfsproc3_null_3(NULL, nfsc->nfs_client);

  /* now connect to the same server on the MOUNT port */

  /* use the portmapper */
  sai.sin_port = 0;

  /* conn->sock[SECONDARYSOCKET] = socket(AF_INET, SOCK_STREAM, 0); */

  sock = conn->sock[SECONDARYSOCKET];

  /* bindresvport(sock, NULL); */

  nfsc->mount_client = clnttcp_create(
    &sai, MOUNTPROG, MOUNTVERS3, &sock, 0, 0);

  if(nfsc->mount_client == NULL) {
    result = CURLE_COULDNT_CONNECT;
  }

  /*
  getsockname(sock, (struct sockaddr *)&getaddr, &len);
  printf("getsockname = %u -> %u\n", ntohs(getaddr.sin_port),
    ntohs(sai.sin_port));
  */

  /* ping */
  status = mountproc_null_3(NULL, nfsc->mount_client);

  if(status) {
    result = CURLE_OK;
  }

  return result;
}

/* callback to call bindresvport() */
int nfs_bindresvport(void *clientp,
                     curl_socket_t curlfd,
                     curlsocktype purpose)
{
  if(bindresvport((int) curlfd, NULL) == 0) {
    return CURL_SOCKOPT_OK;
  }
  else {
    return CURL_SOCKOPT_ERROR;
  }
}

static CURLcode nfs_setup_connection(struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;
  char *type;
  char command;
  struct nfs_conn *nfsc = &conn->proto.nfsc;
  struct NFS *nfs;

  conn->data->req.protop = nfs = calloc(1, sizeof(struct NFS));
  if(NULL == nfs)
    return CURLE_OUT_OF_MEMORY;

  /* make sure we connect from a "secure" port */
  curl_easy_setopt(
    data, CURLOPT_SOCKOPTFUNCTION, nfs_bindresvport);

  return CURLE_OK;
}

/* convert an NFS filehandle to a string */
char *nfs_fh3_to_string(nfs_fh3 file_handle)
{
    unsigned int i;
    /* allocate space for output string */
    /* 2 characters per byte plus NULL */
    char *str = calloc((file_handle.data.data_len * 2) + 1, sizeof(char));

    for(i = 0; i < file_handle.data.data_len; i++) {
        /* each input byte is two output bytes (in hex) */
        /* plus terminating NUL */
        snprintf(&str[i * 2], 3, "%02hhx", file_handle.data.data_val[i]);
    }

    /* terminating NUL */
    str[i * 2] = '\0';

    return str;
}

/* lookup the filehandle */
CURLcode nfs_do(struct connectdata *conn, bool *done)
{
  CURLcode result = CURLE_OK;
  struct nfs_conn *nfsc = &conn->proto.nfsc;
  struct Curl_easy *data = conn->data;
  char *path = data->state.path;
  mountres3 *mountres = NULL;
  READ3res *res;
  READ3args args;

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, -1);
  Curl_pgrsSetDownloadSize(data, -1);

  mountres = mountproc_mnt_3(&path, nfsc->mount_client);

  if(mountres && (mountres->fhs_status == MNT3_OK)) {
    /* copy the resulting filehandle */
    nfsc->fh.data.data_val = calloc(
      mountres->mountres3_u.mountinfo.fhandle.fhandle3_len, sizeof(char));
    memcpy(nfsc->fh.data.data_val,
      mountres->mountres3_u.mountinfo.fhandle.fhandle3_val,
      mountres->mountres3_u.mountinfo.fhandle.fhandle3_len);
    nfsc->fh.data.data_len =
      mountres->mountres3_u.mountinfo.fhandle.fhandle3_len;
    /* free the handle in the client */
    clnt_freeres(nfsc->mount_client,
      (xdrproc_t) xdr_mountres3, (caddr_t) mountres);

    /* start at the beginning of the file */
    nfsc->offset = 0;
  }

  /* read the file */
  args.file = nfsc->fh;
  args.count = 16384;

  do
  {
    args.offset = nfsc->offset;

    res = nfsproc3_read_3(&args, nfsc->nfs_client);

    if(res) {
      if(res->status == NFS3_OK) {
        /* write output */
        Curl_client_write(conn, CLIENTWRITE_BODY,
          res->READ3res_u.resok.data.data_val,
          res->READ3res_u.resok.data.data_len);

        nfsc->offset += res->READ3res_u.resok.count;

        Curl_pgrsSetDownloadCounter(data,
          (curl_off_t) nfsc->offset);

        if(res->READ3res_u.resok.eof) {
          *done = TRUE;
          Curl_pgrsDone(conn);
        }
        else {
          Curl_pgrsUpdate(conn);
        }

        /* free memory in the client */
        clnt_freeres(nfsc->nfs_client,
          (xdrproc_t) xdr_READ3res, (caddr_t) res);
      }
    }
  }
  while(res && res->status == NFS3_OK && res->READ3res_u.resok.eof == 0);

  return result;
}

#endif /* CURL_DISABLE_NFS */
