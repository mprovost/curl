#ifndef HEADER_CURL_NFS_H
#define HEADER_CURL_NFS_H

#include <rpc/rpc.h>

#ifndef CURL_DISABLE_NFS
extern const struct Curl_handler Curl_handler_nfs;

#endif /* CURL_DISABLE_NFS */

struct nfs_conn {
  CLIENT *client;
};

#endif /* HEADER_CURL_NFS_H */
