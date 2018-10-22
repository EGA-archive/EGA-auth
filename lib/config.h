
#ifndef __LEGA_CONFIG_H_INCLUDED__
#define __LEGA_CONFIG_H_INCLUDED__

#include <stdbool.h>
#include <sys/types.h> 

struct options_s {
  char* cfgfile;
  char* buffer;
  
  gid_t gid;               /* group id for all EGA users */
  uid_t uid_shift;         /* added to the user id from CentralEGA */
  char* shell;             /* User shell. Defaults to /bin/bash */

  char* db_path;           /* db file path */

  /* Homedir */
  char* ega_dir;           /* EGA main inbox directory */
  long int ega_dir_attrs;  /* in octal form */
  mode_t ega_dir_umask;    /* user process's mask */
  bool chroot;             /* sandboxing the users in their home directory */

  /* Contacting Central EGA (vie REST call) */
  char* idp_url;           /* Identity Provider URL */
  char* client_id;         /* Client ID used by the IdP */
  char* client_secret;     /* Client Secret used by the IdP */
  char* redirect_uri;      /* Where the IdP sends us back. TODO: URL-encode it? */
  unsigned int interval;   /* Sleep interval before checking for token again */
  unsigned int repeat;     /* Max number of checks */
};

typedef struct options_s options_t;

extern options_t* options;

bool loadconfig(const char* filepath);
void cleanconfig(void);

#endif /* !__LEGA_CONFIG_H_INCLUDED__ */
