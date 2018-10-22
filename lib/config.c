#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <strings.h>

#include "utils.h"
#include "config.h"

#define CFGFILE "/etc/ega/auth.conf"
#define UMASK 0027 /* no permission for world */

#define EGA_UID_SHIFT 10000
#define EGA_SHELL "/bin/bash"

#define ENABLE_CHROOT false
#define CHROOT_OPTION "chroot_sessions"

#define QR_INTERVAL 5 // in seconds.
#define QR_REPEAT 12  // That makes it one minute to timeout

options_t* options = NULL;
char* syslog_name = "EGA";

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

  D2("Checking the config struct | Loaded from %s", options->cfgfile);
  if(options->uid_shift < 0      ) { D3("Invalid ega_uid_shift");    valid = false; }
  if(options->gid < 0            ) { D3("Invalid ega_gid");          valid = false; }

  if(!options->shell             ) { D3("Invalid shell");            valid = false; }

  if(!options->ega_dir           ) { D3("Invalid ega_dir");          valid = false; }
  if(!options->ega_dir_attrs     ) { D3("Invalid ega_dir_attrs");    valid = false; }
  if(!options->ega_dir_umask     ) { D3("Invalid ega_dir_umask");    valid = false; }

  if(!options->db_path           ) { D3("Invalid db_path");          valid = false; }

  if(!options->idp_url           ) { D3("Invalid idp_url");          valid = false; }
  if(!options->client_id         ) { D3("Invalid client_id");        valid = false; }
  if(!options->client_secret     ) { D3("Invalid client_secret");    valid = false; }
  if(!options->redirect_uri      ) { D3("Invalid redirect_uri");     valid = false; }

  if(options->interval <= 0      ) { D3("Invalid interval");         valid = false; }
  if(options->repeat <= 0        ) { D3("Invalid repeat");           valid = false; }

  if(!valid){ D3("Invalid config struct from %s", options->cfgfile); }
  return valid;
}

#define INJECT_OPTION(key,ckey,val,loc) do { if(!strcmp(key, ckey) && copy2buffer(val, &(loc), &buffer, &buflen) < 0 ){ return -1; } } while(0)
#define COPYVAL(val,dest) do { if( copy2buffer(val, &(dest), &buffer, &buflen) < 0 ){ return -1; } } while(0)

static inline int
readconfig(FILE* fp, const char* cfgfile, char* buffer, size_t buflen)
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

  options->interval = QR_INTERVAL;
  options->repeat = QR_REPEAT;

  COPYVAL(CFGFILE   , options->cfgfile          );
  COPYVAL(EGA_SHELL , options->shell            );

  /* Config file location */
  COPYVAL(cfgfile   , options->cfgfile          );

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
    if(!strcmp(key, "ega_gid"       )) { if( !sscanf(val, "%u" , &(options->gid)   )) options->gid = -1; }
   
    INJECT_OPTION(key, "db_path"      , val, options->db_path      );
    INJECT_OPTION(key, "ega_dir"      , val, options->ega_dir      );
    INJECT_OPTION(key, "ega_shell"    , val, options->shell        );
    INJECT_OPTION(key, "idp_url"      , val, options->idp_url      );
    INJECT_OPTION(key, "client_id"    , val, options->client_id    );
    INJECT_OPTION(key, "client_secret", val, options->client_secret);
    INJECT_OPTION(key, "redirect_uri" , val, options->redirect_uri );

    if(!strcmp(key, "interval") && !sscanf(val, "%u" , &(options->interval) )) {
      D2("Could not parse interval: Using %u instead.", options->interval);
    }
    if(!strcmp(key, "repeat") && !sscanf(val, "%u" , &(options->repeat) )) {
      D2("Could not parse repeat: Using %u instead.", options->repeat);
    }

    if(!strcmp(key, CHROOT_OPTION)) {
      if(!strcasecmp(val, "yes") || !strcasecmp(val, "true") || !strcmp(val, "1") || !strcasecmp(val, "on")){
	options->chroot = true;
      } else if(!strcasecmp(val, "no") || !strcasecmp(val, "false") || !strcmp(val, "0") || !strcasecmp(val, "off")){
	options->chroot = false;
      } else {
	D2("Could not parse the "CHROOT_OPTION": Using %s instead.", ((options->chroot)?"yes":"no"));
      }
    }	
  }

  D1(CHROOT_OPTION": %s", ((options->chroot)?"yes":"no"));

  return 0;
}

bool
loadconfig(const char* filepath)
{
  const char* cfgfile = (filepath)?filepath:CFGFILE;

  D1("Loading configuration %s", cfgfile);
  if(options && !strcmp(options->cfgfile,cfgfile)){ D2("Already loaded [@ %p]", options); return true; }

  _cleanup_file_ FILE* fp = NULL;
  size_t size = 1024;
  
  /* read or re-read */
  fp = fopen(cfgfile, "r");
  if (fp == NULL || errno == EACCES) { D2("Error accessing the config file: %s", strerror(errno)); return false; }

  options = (options_t*)malloc(sizeof(options_t));
  if(!options){ D3("Could not allocate options data structure"); return false; };
  options->buffer = NULL;

REALLOC:
  D3("Allocating buffer of size %zd", size);
  if(options->buffer)free(options->buffer);
  options->buffer = malloc(sizeof(char) * size);
  if(!options->buffer){ D3("Could not allocate buffer of size %zd", size); return false; };

  memset(options->buffer, '\0', size);
  /* *(options->buffer) = '\0'; */
  
  if( readconfig(fp, cfgfile, options->buffer, size) < 0 ){
    size = size << 1; // double it
    goto REALLOC;
  }

  D2("Conf loaded [@ %p]", options);

#ifdef DEBUG
  return valid_options();
#else
  return true;
#endif
}
