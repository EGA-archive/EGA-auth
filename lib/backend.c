#include <stdio.h>
#include <time.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <errno.h>
#include <syslog.h>
#include <sqlite3.h>
#include <unistd.h>

#if SQLITE_VERSION_NUMBER < 3024000
  #error Only SQLite 3.24+ supported
#endif

#include "config.h"
#include "utils.h"
#include "backend.h"

/* DB schema */
#define EGA_SCHEMA_USERS  "CREATE TABLE IF NOT EXISTS users (                        \
                               username TEXT UNIQUE PRIMARY KEY ON CONFLICT REPLACE, \
                               uid      INTEGER CHECK (uid >= %d),                   \
		               gecos    TEXT					     \
                           ) WITHOUT ROWID;"
#define EGA_SCHEMA_TOKENS "CREATE TABLE IF NOT EXISTS tokens (                       \
                               user          INTEGER NOT NULL REFERENCES users (uid),\
                               session_id    UNIQUE PRIMARY KEY ON CONFLICT REPLACE, \
		               access_token  TEXT NOT NULL,			     \
                               id_token      TEXT                                    \
                           ) WITHOUT ROWID;"
/* WITHOUT ROWID works only from 3.8.2 */


static sqlite3* db = NULL;

static inline bool
backend_opened(void)
{
  return db != NULL && sqlite3_errcode(db) == SQLITE_OK;
}

void
backend_open(void)
{
  if( backend_opened() ){ D1("Already opened"); return; }

  D1("Opening backend");
  if( !loadconfig(NULL) ){ REPORT("Invalid configuration"); return; }

  D1("Connection to: %s", options->db_path);
  sqlite3_open(options->db_path, &db); /* owned by root and rw-r--r-- */
  if (db == NULL){ D1("Failed to allocate database handle"); return; }
  D3("DB Connection: %p", db);
  
  if( sqlite3_errcode(db) != SQLITE_OK) {
    D1("Failed to open DB: [%d] %s", sqlite3_extended_errcode(db), sqlite3_errstr(sqlite3_extended_errcode(db)));
    return;
  }
  
  /* create table */
  D2("Creating the database schema");
  sqlite3_stmt *stmt;
  char schema[1000]; /* Laaaarge enough! */
  sprintf(schema, EGA_SCHEMA_USERS, options->uid_shift);
  sqlite3_prepare_v2(db, schema, -1, &stmt, NULL);
  if (!stmt || sqlite3_step(stmt) != SQLITE_DONE) { D1("ERROR creating table: %s", sqlite3_errmsg(db)); }
  sqlite3_finalize(stmt);
  sqlite3_prepare_v2(db, EGA_SCHEMA_TOKENS, -1, &stmt, NULL);
  if (!stmt || sqlite3_step(stmt) != SQLITE_DONE) { D1("ERROR creating table: %s", sqlite3_errmsg(db)); }
  sqlite3_finalize(stmt);
}

void
backend_close(void)
{
  D1("Closing database backend");
  if(db) sqlite3_close(db);
  cleanconfig();
}

/*
 * Constructor/Destructor when the library is loaded
 *
 * See: http://man7.org/linux/man-pages/man3/dlopen.3.html
 *
 */
__attribute__((constructor))
static void
init(void)
{
  D3("Initializing the ega library");
  backend_open();
#ifdef DEBUG
  openlog (syslog_name, (LOG_CONS|LOG_NDELAY|LOG_PID), 0);
#endif
}

__attribute__((destructor))
static void
destroy(void)
{
  D3("Cleaning up the ega library");
#ifdef DEBUG
  closelog ();
#endif
  backend_close(); 
}


static inline int
_col2uid(sqlite3_stmt *stmt, int col, uid_t *uid)
{
  if(sqlite3_column_type(stmt, col) != SQLITE_INTEGER){ D1("Column %d is not a int", col); return 1; }
  *uid = (uid_t)sqlite3_column_int(stmt, col);
  /* if( *uid <= options->uid_shift ){ D1("User id too low: %u", *uid); return 2; } */
  return 0;
}

static inline int
_col2txt(sqlite3_stmt *stmt, int col, char** data, char **buffer, size_t* buflen)
{
  if(sqlite3_column_type(stmt, col) != SQLITE_TEXT){ D1("The colum %d is not a string", col); return 1; }
  char* s = (char*)sqlite3_column_text(stmt, col);
  if( s == NULL ){ D1("Memory allocation error"); return 1; }
  if( copy2buffer(s, data, buffer, buflen) < 0 ) { return -1; }
  return 0;
}

/*
 * 'convert' to struct passwd
 *
 * We use -1 in case the buffer is too small
 *         0 on success
 *         1 on cache miss / user not found
 *         error otherwise
 *
 * Note: Those functions ignore the expiration column
 */

int backend_getpwuid_r(uid_t uid, struct passwd *result, char *buffer, size_t buflen)
{
  if(!backend_opened()) return 2;

  sqlite3_stmt *stmt = NULL;
  int rc = 1; /* cache miss */
  D2("select username,uid,gecos from users where uid = %u LIMIT 1", uid);
  sqlite3_prepare_v2(db, "select username,uid,gecos from users where uid = ?1 LIMIT 1", -1, &stmt, NULL);
  if(stmt == NULL){ D1("Prepared statement error: %s", sqlite3_errmsg(db)); return rc; }
  sqlite3_bind_int(stmt, 1, uid);

  /* cache miss */
  if(sqlite3_step(stmt) != SQLITE_ROW) { D2("No SQL row"); goto BAILOUT; }

  /* Convert to struct PWD */
  if( (rc = _col2txt(stmt, 0, &(result->pw_name), &buffer, &buflen)) ) goto BAILOUT;
  if( copy2buffer("x", &(result->pw_passwd), &buffer, &buflen) < 0 ){ rc = -1; goto BAILOUT; }
  result->pw_uid = uid;
  result->pw_gid = options->gid;
  if( (rc = _col2txt(stmt, 2, &(result->pw_gecos), &buffer, &buflen)) ) goto BAILOUT;
  char* homedir = strjoina(options->ega_dir, "/", result->pw_name);
  D3("Username %s [%s]", result->pw_name, homedir);
  if( copy2buffer(homedir, &(result->pw_dir), &buffer, &buflen) < 0 ){ rc = -1; goto BAILOUT; }
  if( copy2buffer(options->shell, &(result->pw_shell), &buffer, &buflen) < 0 ){ rc = -1; goto BAILOUT; }

  /* success */ rc = 0;
BAILOUT:
  sqlite3_finalize(stmt);
  return rc;
};

int
backend_getpwnam_r(const char* username, struct passwd *result, char* buffer, size_t buflen)
{
  if(!backend_opened()) return 2;
  sqlite3_stmt *stmt = NULL;
  int rc = 1; /* cache miss */
  D2("select username,uid,gecos from users where username = '%s' LIMIT 1", username);
  sqlite3_prepare_v2(db, "select username,uid,gecos from users where username = ?1 LIMIT 1", -1, &stmt, NULL);
  if(stmt == NULL){ D1("Prepared statement error: %s", sqlite3_errmsg(db)); return false; }
  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

  /* cache miss */
  if(sqlite3_step(stmt) != SQLITE_ROW) { D2("No SQL row"); goto BAILOUT; }

  /* Convert to struct PWD */
  result->pw_name = (char*)username;
  /* if( (rc = _col2txt(stmt, 0, &(result->pw_name), &buffer, &buflen)) ){ rc = -1; goto BAILOUT; } */
  if( copy2buffer("x"     , &(result->pw_passwd), &buffer, &buflen) < 0 ){ rc = -1; goto BAILOUT; }
  if( (rc = _col2uid(stmt, 1, &(result->pw_uid))) ) goto BAILOUT;
  result->pw_gid = options->gid;
  if( (rc = _col2txt(stmt, 2, &(result->pw_gecos), &buffer, &buflen)) ) goto BAILOUT;
  char* homedir = strjoina(options->ega_dir, "/", username);
  D3("Username %s [%s]", username, homedir);
  if( copy2buffer(homedir, &(result->pw_dir), &buffer, &buflen) < 0 ){ rc = -1; goto BAILOUT; }
  if( copy2buffer(options->shell, &(result->pw_shell), &buffer, &buflen) < 0 ){ rc = -1; goto BAILOUT; }

  /* success */ rc = 0;
BAILOUT:
  sqlite3_finalize(stmt);
  return rc;
}



/* ================================================================ */

static bool
_backend_has_token(const char* session_id)
{
  sqlite3_stmt *stmt = NULL;
  bool exists = false;

  D1("Find session id %s into cache", session_id);

  sqlite3_prepare_v2(db, "SELECT EXISTS(SELECT 1 FROM tokens WHERE session_id = ?1 LIMIT 1);", -1, &stmt, NULL);
  if(!stmt){ D1("Prepared statement error: %s", sqlite3_errmsg(db)); return false; }

  sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_STATIC);

  /* Execute the query. */
  if(sqlite3_step(stmt) != SQLITE_ROW) { D2("No SQL row"); goto BAILOUT; }

  /* if(sqlite3_column_type(stmt, 0) != SQLITE_INTEGER){ D1("Column 0 is not a int"); return 1; } */
  exists = (sqlite3_column_int(stmt, 0))?true:false;

  D1("sqlite3_column_type(stmt, 0): %d", sqlite3_column_type(stmt, 0));
  D1("sqlite3_column_int(stmt, 0): %d", sqlite3_column_int(stmt, 0));

  if( sqlite3_step(stmt) != SQLITE_DONE ){ exists = false; D1("Execution error: %s", sqlite3_errmsg(db)); }

BAILOUT:
  sqlite3_finalize(stmt);
  return exists;
}


bool
backend_has(const char* session_id)
{
  if(!backend_opened()) return false;
  unsigned int repeat = options->repeat, canceled;
  do {
    if(_backend_has_token(session_id)) return true;
    canceled = sleep(options->interval);
  } while (repeat-- > 0 && !canceled);
  D1("Token not landed within %d seconds", options->interval * options->repeat);
  return false;
}
