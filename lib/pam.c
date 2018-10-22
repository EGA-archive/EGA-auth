#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <uuid/uuid.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCT
#define PAM_SM_SESSION
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include <limits.h>

#include "utils.h"
#include "config.h"
#include "backend.h"
#include "homedir.h"
#include "qr.h"

#define PAM_OPT_DEBUG			0x01
/* ... more ?*/

/*
 * Fetch module options
 */
void pam_options(int *flags, int argc, const char **argv)
{
  char** args = (char**)argv;
  char* config_file = NULL;
  /* Step through module arguments */
  for (; argc-- > 0; ++args){
    if (!strcmp(*args, "silent")) {
      *flags |= PAM_SILENT;
    } else if (!strcmp(*args, "debug")) {
      *flags |= PAM_OPT_DEBUG;
    /* } else if (!strcmp(*args, "echo_pass")) { */
    /*   *flags |= PAM_OPT_ECHO_PASS; */
    } else if (!strncmp(*args,"config_file=",12)) {
      config_file = *args+12;
    } else {
      D1("unknown option: %s", *args);
    }
  }

  loadconfig(config_file);

  return;
}

/*
 * authenticate user
 */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  const char *user = NULL;
  const void *item;
  int rc;
  int mflags = 0;
  
  D2("Getting auth PAM module options");

  rc = pam_get_user(pamh, &user, NULL);
  if (rc != PAM_SUCCESS) { D1("Can't get user: %s", pam_strerror(pamh, rc)); return rc; }
  
  rc = pam_get_item(pamh, PAM_RHOST, &item);
  if ( rc != PAM_SUCCESS) { D1("EGA: Unknown rhost: %s", pam_strerror(pamh, rc)); }
  D1("Authenticating %s%s%s", user, (item)?" from ":"", (item)?((char*)item):"");

  /* Get PAM options */
  pam_options(&mflags, argc, argv);

  /* Generate a new Session ID */
  _cleanup_str_ char* session_id = NULL;
  make_session_id(&session_id);
  D1("Session ID: %s", session_id);

  /* Prepare URL */
  char* query = strjoina("client_id=", options->client_id,
			 "&response_type=code&redirect_uri=", options->redirect_uri,
			 "&scope=openid+profile&state=", (char*)session_id);
  char* url = strjoina(options->idp_url, "?", query); // no need to URL-encode, we were careful
  D1("URL: %s", url);

  /* Preparing the prompt */
  D1("Showing QR code for %s", user);

  _cleanup_str_ char* qrcode = NULL;
  if (make_qrcode(url, &qrcode)) { D1("EGA: Could not make the QR code"); return PAM_AUTH_ERR; }
  
  D1("Preparing conversation");
  rc = pam_get_item(pamh, PAM_CONV, &item);
  if (rc != PAM_SUCCESS){ D1("Conversation initialization failed: %s", pam_strerror(pamh, rc)); return rc; }

  const struct pam_conv *conv = (struct pam_conv *)item;
  const struct pam_message *msgs[1];
  struct pam_message msg;
  struct pam_response* resp;

  D1("Preparing information message");
  msg.msg_style = PAM_PROMPT_ECHO_OFF; //PAM_TEXT_INFO;
  msg.msg = strjoina("QR scan the following code\n\n",
		     qrcode,
		     "\n\nor copy the following URL in your browser, for authentication\n\n",
		     url,
		     "\n\nHit <Enter> when you are ready"); // on the stack!
  msgs[0] = &msg;

  D1("Display messages to the user");
  rc = (*conv->conv)(1, msgs, &resp, conv->appdata_ptr);
  if (rc != PAM_SUCCESS){ D1("QR conversation failed: %s", pam_strerror(pamh, rc)); return rc; }
  
  D1("Cleaning responses");
  if(resp->resp){
    memset(resp->resp, 0, strlen(resp->resp));
    free(resp->resp);
    //free(resp);
  }

  /* Now, we wait for the token */
  D1("Waiting for token for session id: %s", session_id);
  if(backend_has(session_id)){
    D1("Authentication successful for %s", user);
    return PAM_SUCCESS;
  }

  D1("Authentication failed for %s", user);
  return PAM_AUTH_ERR;
}

/*
 * Create and Chroot to homedir
 */
PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  const char *username;
  int rc;
  int mflags = 0;

  D2("Getting open session PAM module options");
  pam_options(&mflags, argc, argv);

  if ( (rc = pam_get_user(pamh, &username, NULL)) != PAM_SUCCESS) { D1("EGA: Unknown user: %s", pam_strerror(pamh, rc)); return rc; }

  /* Construct homedir */
  char *homedir = strjoina(options->ega_dir, "/", username);
  D1("Username: %s, Homedir %s", username, homedir);

  /* Handling umask */
  D1("Setting umask to %o", options->ega_dir_umask);
  umask((mode_t)options->ega_dir_umask); /* ignore old mask */
  
  if( options->chroot ){
    D1("Chrooting to %s", homedir);
    if (chdir(homedir)) { D1("Unable to chdir to %s: %s", homedir, strerror(errno)); return PAM_SESSION_ERR; }
    if (chroot(homedir)){ D1("Unable to chroot(%s): %s", homedir, strerror(errno)); return PAM_SESSION_ERR; }
    if (chdir("/")){ D1("Unable to chdir(/) after chroot(%s): %s", homedir, strerror(errno)); return PAM_SESSION_ERR; }
  } else {
    D1("Chrooting disabled");
  }

  D1("Session open: Success");
  return PAM_SUCCESS;
}

/*
 * Returning success because we are in the chrooted env
 * so no path to the user's cache entry
 */
PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
  D1("Session close: Success");
  return PAM_SUCCESS;
}


/* Allow the account */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
  D1("Account: Create the homedir");
  const char *username;
  int rc;
  int mflags = 0;

  D2("Getting open session PAM module options");
  pam_options(&mflags, argc, argv);

  if ( (rc = pam_get_user(pamh, &username, NULL)) != PAM_SUCCESS) { D1("EGA: Unknown user: %s", pam_strerror(pamh, rc)); return rc; }

  /* Fetch home directory passwd entry (using NSS) */
  char* buffer = NULL;
  size_t buflen = 1024;
  struct passwd result;

REALLOC:
  D3("Allocating buffer of size %zd", buflen);
  if(buffer)free(buffer);
  buffer = malloc(sizeof(char) * buflen);
  if(!buffer){ D3("Could not allocate buffer of size %zd", buflen); return -1; };
  /* memset(buffer, '\0', size); */
  *buffer = '\0';

  if( backend_getpwnam_r(username, &result, buffer, buflen) < 0 ){
    buflen = buflen << 1; /* double it */
    goto REALLOC;
  }

  if( create_ega_dir(&result) ){ D1("Could not create the homedir %s ", result.pw_dir); return PAM_AUTH_ERR; };

  D1("Account succeeded for %s", username);
  return PAM_SUCCESS;
}

/*
 * setcred runs before and after session_open
 * which means, 'after' is in a chrooted-env, so setcred fails
 * (but before succeeds)
 * So a user is refreshed right before an attempts to open a session,
 * right after a successful authentication
 */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  D1("Set cred allowed");
  return PAM_SUCCESS;
}
