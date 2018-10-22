#ifndef __LEGA_BACKEND_H_INCLUDED__
#define __LEGA_BACKEND_H_INCLUDED__

#include <stdbool.h>
#include <pwd.h>

int backend_getpwnam_r(const char* username, struct passwd *result, char *buffer, size_t buflen);
int backend_getpwuid_r(uid_t uid, struct passwd *result, char *buffer, size_t buflen);

bool backend_has(const char* session_id);

#endif /* !__LEGA_BACKEND_H_INCLUDED__ */
