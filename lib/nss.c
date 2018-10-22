#include <nss.h>
#include <pwd.h>
#include <errno.h>

#include "utils.h"
#include "config.h"
#include "backend.h"

/*
 * - passwd functions
 * - no group functions
 */

/* Not allowed */
enum nss_status _nss_ega_setpwent (void){ D1("called"); return NSS_STATUS_UNAVAIL; }
enum nss_status _nss_ega_endpwent(void){ D1("called"); return NSS_STATUS_UNAVAIL; }
enum nss_status _nss_ega_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop){ D1("called"); return NSS_STATUS_UNAVAIL; }

enum nss_status
_nss_ega_getpwuid_r(uid_t uid, struct passwd *result,
		    char *buffer, size_t buflen, int *errnop)
{
  /* bail out if we're looking for the root user */
  /* if( !strcmp(username, "root") ){ D1("bail out when root"); return NSS_STATUS_NOTFOUND; } */

  if( uid == (uid_t)(-1) ){ D2("ignoring -1"); return NSS_STATUS_NOTFOUND; }

  uid_t ruid = uid - options->uid_shift; 
  D1("Looking up user id %u [remotely %u]", uid, ruid);
  if( ruid <= 0 ){ D2("... too low: ignoring"); return NSS_STATUS_NOTFOUND; }

  switch( backend_getpwuid_r(uid, result, buffer, buflen) ){
  case -1:
    D1("Buffer too small");
    *errnop = ERANGE;
    return NSS_STATUS_TRYAGAIN;
    //break;
  case 0:
    REPORT("User id %u found in cache", uid);
    *errnop = 0;
    return NSS_STATUS_SUCCESS;
    //break;
  default:
    D2("UID %u not found", ruid);
    return NSS_STATUS_NOTFOUND;
  }
}

/* Find user ny name */
enum nss_status
_nss_ega_getpwnam_r(const char *username, struct passwd *result,
		    char *buffer, size_t buflen, int *errnop)
{
  /* bail out if we're looking for the root user */
  /* if( !strcmp(username, "root") ){ D1("bail out when root"); return NSS_STATUS_NOTFOUND; } */

  D1("Looking up '%s'", username);
  /* memset(buffer, '\0', buflen); */

  switch( backend_getpwnam_r(username, result, buffer, buflen) ){
  case -1:
    D1("Buffer too small");
    *errnop = ERANGE;
    return NSS_STATUS_TRYAGAIN;
    //break;
  case 0:
    REPORT("User %s found in cache", username);
    *errnop = 0;
    return NSS_STATUS_SUCCESS;
    //break;
  default:
    D2("User %s not found", username);
    return NSS_STATUS_NOTFOUND;
  }
}
