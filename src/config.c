#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <strings.h>
#include <stdio.h>

#include "utils.h"
#include "config.h"

#define CFGFILE "/etc/ega/auth.conf"
#define PROMPT "Please, enter your EGA password: "
#define UMASK 0027 /* no permission for world */

#define CACHE_TTL 3600 // 1h in seconds.
#define EGA_UID_SHIFT 10000
#define EGA_SHELL "/bin/bash"

#define ENABLE_CHROOT false
#define CHROOT_OPTION "chroot_sessions"

#define VERIFY_PEER false
#define VERIFY_HOSTNAME false

options_t* options = NULL;
char* syslog_name = "EGA-auth";

static inline void set_yes_no_option(char* key, char* val, char* name, bool* loc);

void
cleanconfig(void)
{
  if(!options) return;
  D2("Cleaning configuration [%p]", options);

  if(options->buffer){ free((char*)options->buffer); }
  free(options);
  return;
}


bool
valid_options(void)
{
  bool valid = true;
  if(!options) { D3("No config struct"); return false; }

  D2("Checking the config struct");
  if(options->cache_ttl < 0.0    ) { D3("Invalid cache_ttl");        valid = false; }
  if(options->uid_shift < 0      ) { D3("Invalid ega_uid_shift");    valid = false; }
  if(options->gid < 0            ) { D3("Invalid ega_gid");          valid = false; }

  if(!options->shell             ) { D3("Invalid shell");            valid = false; }
  if(!options->prompt            ) { D3("Invalid prompt");           valid = false; }

  if(!options->ega_dir           ) { D3("Invalid ega_dir");          valid = false; }
  if(!options->ega_dir_attrs     ) { D3("Invalid ega_dir_attrs");    valid = false; }
  if(!options->ega_dir_umask     ) { D3("Invalid ega_dir_umask");    valid = false; }

  if(!options->db_path           ) { D3("Invalid db_path");          valid = false; }

  if(!options->cega_creds        ) { D3("Invalid cega_creds");       valid = false; }
  if(!options->cega_endpoint_username) { D3("Invalid cega_endpoint for usernames");    valid = false; }
  if(!options->cega_endpoint_uid ) { D3("Invalid cega_endpoint for user ids");    valid = false; }

  if(options->verify_peer &&
     !options->cacertfile){ D3("Missing cacertfile, when using verify_peer"); valid = false; }

  if(!!options->certfile ^ !!options->keyfile){
    D3("Either certfile or keyfile is missing");
    valid = false;
  }

  if(!valid){ D3("Invalid config struct from %s", options->cfgfile); }
  return valid;
}

#define INJECT_OPTION(key,ckey,val,loc) do { if(!strcmp(key, ckey) && copy2buffer(val, loc, &buffer, &buflen) < 0 ){ return -1; } } while(0)
#define COPYVAL(val,dest,b,blen) do { if( copy2buffer(val, dest, b, blen) < 0 ){ return -1; } } while(0)

static inline int
readconfig(FILE* fp, char* buffer, size_t buflen)
{
  D3("Reading configuration file");
  _cleanup_str_ char* line = NULL;
  size_t len = 0;
  char *key,*eq,*val,*end;

  /* Default config values */
  options->uid_shift = EGA_UID_SHIFT;
  options->gid = -1;
  options->chroot = ENABLE_CHROOT;
  options->ega_dir_umask = (mode_t)UMASK;
  options->cache_ttl = CACHE_TTL;

  options->cega_endpoint_username_len = 0;
  options->cega_endpoint_uid_len = 0;

  /* TLS settings */
  options->verify_peer = VERIFY_PEER;
  options->verify_hostname = VERIFY_HOSTNAME;
  options->cacertfile = NULL;
  options->certfile = NULL;
  options->keyfile = NULL;

  COPYVAL(CFGFILE   , &(options->cfgfile), &buffer, &buflen );
  COPYVAL(PROMPT    , &(options->prompt) , &buffer, &buflen );
  COPYVAL(EGA_SHELL , &(options->shell)  , &buffer, &buflen );
  options->cega_json_prefix = '\0'; /* default */

  /* Parse line by line */
  while (getline(&line, &len, fp) > 0) {
	
    key=line;
    /* remove leading whitespace */
    while(isspace(*key)) key++;
      
    if((eq = strchr(line, '='))) {
      end = eq - 1; /* left of = */
      val = eq + 1; /* right of = */
	  
      /* find the end of the left operand */
      while(end > key && isspace(*end)) end--;
      *(end+1) = '\0';
	  
      /* find where the right operand starts */
      while(*val && isspace(*val)) val++;
	  
      /* find the end of the right operand */
      eq = val;
      while(*eq != '\0') eq++;
      eq--;
      if(*eq == '\n') { *eq = '\0'; } /* remove new line */
	  
    } else val = NULL; /* could not find the '=' sign */
	
    if(!strcmp(key, "ega_dir_umask" )) { options->ega_dir_umask = strtol(val, NULL, 8); } /* ok when val contains a comment #... */
    if(!strcmp(key, "ega_dir_attrs" )) { options->ega_dir_attrs = strtol(val, NULL, 8); }
    if(!strcmp(key, "ega_uid_shift" )) { if( !sscanf(val, "%u" , &(options->uid_shift) )) options->uid_shift = -1; }
    if(!strcmp(key, "cache_ttl"     )) { if( !sscanf(val, "%u" , &(options->cache_ttl) )) options->cache_ttl = -1; }
    if(!strcmp(key, "ega_gid"       )) { if( !sscanf(val, "%u" , &(options->gid)   )) options->gid = -1; }
   
    INJECT_OPTION(key, "db_path"           , val, &(options->db_path)          );
    INJECT_OPTION(key, "ega_dir"           , val, &(options->ega_dir)          );
    INJECT_OPTION(key, "prompt"            , val, &(options->prompt)           );
    INJECT_OPTION(key, "ega_shell"         , val, &(options->shell)            );
    INJECT_OPTION(key, "cega_endpoint_username", val, &(options->cega_endpoint_username));
    INJECT_OPTION(key, "cega_endpoint_uid" , val, &(options->cega_endpoint_uid));
    INJECT_OPTION(key, "cega_creds"        , val, &(options->cega_creds)       );
    INJECT_OPTION(key, "cega_json_prefix"  , val, &(options->cega_json_prefix) );
    INJECT_OPTION(key, "cacertfile"        , val, &(options->cacertfile)       );
    INJECT_OPTION(key, "certfile"          , val, &(options->certfile)         );
    INJECT_OPTION(key, "keyfile"           , val, &(options->keyfile)          );


    set_yes_no_option(key, val, CHROOT_OPTION, &(options->chroot));
    set_yes_no_option(key, val, "verify_peer", &(options->verify_peer));
    set_yes_no_option(key, val, "verify_hostname", &(options->verify_hostname));
  }

  D1(CHROOT_OPTION": %s", ((options->chroot)?"yes":"no"));
  D1("verify_peer: %s", ((options->verify_peer)?"yes":"no"));
  D1("verify_hostname: %s", ((options->verify_hostname)?"yes":"no"));

  if(options->cega_endpoint_username)
    options->cega_endpoint_username_len = strlen(options->cega_endpoint_username) - 1; /* count away %u, add \0 */
  if(options->cega_endpoint_uid)
    options->cega_endpoint_uid_len = strlen(options->cega_endpoint_uid) - 1; /* count away %u, add \0 */

  return 0;
}

bool
loadconfig(void)
{
  D1("Loading configuration %s", CFGFILE);
  if(options){ D2("Already loaded [@ %p]", options); return true; }

  _cleanup_file_ FILE* fp = NULL;
  size_t size = 1024;
  
  /* read or re-read */
  fp = fopen(CFGFILE, "r");
  if (fp == NULL || errno == EACCES) { D2("Error accessing the config file: %s", strerror(errno)); return false; }

  options = (options_t*)malloc(sizeof(options_t));
  if(!options){ D3("Could not allocate options data structure"); return false; };
  options->buffer = NULL;

REALLOC:
  D3("Allocating buffer of size %zd", size);
  if(options->buffer)free(options->buffer);
  options->buffer = malloc(sizeof(char) * size);
  memset(options->buffer, '\0', size);
  /* *(options->buffer) = '\0'; */
  if(!options->buffer){ D3("Could not allocate buffer of size %zd", size); return false; };

  if( readconfig(fp, options->buffer, size) < 0 ){

    /* Rewind first */
    if(fseek(fp, 0, SEEK_SET)){ D3("Could not rewind config file to start"); return false; }

    /* Doubling the buffer size */
    size = size << 1;
    goto REALLOC;
  }

  D2("Conf loaded [@ %p]", options);

#if DEBUG
  D1("-------------");
  int i=0;
  char* c = options->buffer;
  for(;i<size;i++,c++){ fprintf(stderr, "%c", *c); }
  fprintf(stderr, "\n");
  D1("-------------");
#endif

#ifdef DEBUG
  return valid_options();
#else
  return true;
#endif
}


static inline void
set_yes_no_option(char* key, char* val, char* name, bool* loc)
{
  if(!strcmp(key, name)) {
    if(!strcasecmp(val, "yes") || !strcasecmp(val, "true") || !strcmp(val, "1") || !strcasecmp(val, "on")){
      *loc = true;
    } else if(!strcasecmp(val, "no") || !strcasecmp(val, "false") || !strcmp(val, "0") || !strcasecmp(val, "off")){
      *loc = false;
    } else {
      D2("Could not parse the %s option: Using %s instead.", name, ((*loc)?"yes":"no"));
    }
  }
}
