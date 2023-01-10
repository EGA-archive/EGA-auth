#ifndef __LEGA_JSON_H_INCLUDED__
#define __LEGA_JSON_H_INCLUDED__

#include "jsmn/jsmn.h"

struct pbk {
  char *pbk;
  struct pbk *next;
};

struct fega_user {
  int uid;
  char* username;
  char* pwdh;
  struct pbk* pubkeys;
  char* gecos;
};

void fega_user_free(struct fega_user *user);

int parse_json(const char* json, int jsonlen, struct fega_user *user);

#endif /* !__LEGA_JSON_H_INCLUDED__ */
