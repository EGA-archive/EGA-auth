#ifndef __LEGA_CENTRAL_H_INCLUDED__
#define __LEGA_CENTRAL_H_INCLUDED__

#include <sys/types.h>

#include "json.h"

int cega_resolve(const char *endpoint, int (*cb)(struct fega_user *));

#endif /* !__LEGA_CENTRAL_H_INCLUDED__ */
