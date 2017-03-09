/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifndef HEADER_CURL_NFS_H
#define HEADER_CURL_NFS_H

#include <rpc/rpc.h> /* general RPC calls */
#include "xdr/mount.h" /* MOUNT protocol */
#include "xdr/nfs_prot.h" /* NFS protocol */

#ifndef CURL_DISABLE_NFS
extern const struct Curl_handler Curl_handler_nfs;

#endif /* CURL_DISABLE_NFS */

struct nfs_conn {
  CLIENT *nfs_client; /* NFS protocol client */
  CLIENT *mount_client; /* MOUNT protocol client */
  struct nfs_fh3 fh; /* NFS filehandle */
};

/* This NFS struct is used in the Curl_easy. All NFS data that is
   connection-oriented must be in nfs_conn to properly deal with the fact that
   perhaps the Curl_easy is changed between the times the connection is
   used. */
struct NFS {
  mountres3 *mountres; /* NFS mount handle */
};

#endif /* HEADER_CURL_NFS_H */
