#include <stdio.h>
#include <sys/types.h>

#include "utils.h"
#include "backend.h"
#include "cega.h"

int
main(int argc, const char **argv)
{
  int rc = 0;

  if( argc < 2 ){ fprintf(stderr, "Usage: %s user\n", argv[0]); return 1; }

  const char* username = argv[1];
  REPORT("Fetching the public key of %s", username);

  /* check database */
  bool use_backend = backend_opened();
  if(use_backend && backend_print_pubkeys(username)) return rc;

  /* Defining the CentralEGA callback */
  int print_pubkey(struct fega_user *user){
    int rc = 1;
    /* assert same name */
    if( strcmp(username, user->username) ){
      REPORT("Requested username %s not matching username response %s", username, user->username);
      return 1;
    }
    if(user->pubkeys){
      struct pbk *current = user->pubkeys;
      while( current ){
	printf("%s\n", current->pbk);
	current = current->next;
      }
    } else {
      REPORT("No ssh key found for user '%s'", username);
    }
    if(use_backend) backend_add_user(user); // ignore result
    return rc;
  }

  _cleanup_str_ char* endpoint = (char*)malloc((options->cega_endpoint_username_len + strlen(username)) * sizeof(char));
  if(!endpoint){ D1("Memory allocation error"); return 1; }
  if(sprintf(endpoint, options->cega_endpoint_username, username) < 0){ D1("Endpoint formatting error"); return 2; }
  return cega_resolve(endpoint, print_pubkey);
}
