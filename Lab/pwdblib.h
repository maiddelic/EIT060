/*
 * Header file for pwdblib.c
 * 
 * 
 */


#include <unistd.h>


/* Define some return values */
#define PWDB_OK 0
#define PWDB_NOUSER -1
#define PWDB_FILEERR -2
#define PWDB_MEMERR -3
#define PWDB_ENTRERR -4
#define PWDB_NULL  -5


/* define the local password file name */
#define PWFILENAME "pwfile"  


/* 
 * Declare structure used for accessing the file 
 * 
 * This stuct conforms with the system struct passwd, except that
 * it has no pw_dir item and two additional items are supplied;
 * pw_failed and pw_age.
 *
 */
struct pwdb_passwd {
  char *pw_name;   /* users login name */
  char *pw_passwd; /* 2 bytes salt value + encrypted password */
  int pw_uid;    /* user id */
  int pw_gid;    /* group id */
  char *pw_gecos;  /* real name */
  char *pw_shell;  /* preferred shell */
  int pw_failed;   /* number of contiguous unsuccessful logins */
  int pw_age;      /* number of successful logins */
};

/* Return error number for function pwdb_getpwnam() */
extern int pwdb_errno;


/* 
 * FUNCTION:
 * struct pwdb_passwd *pwdb_getpwnam(char *name)
 *
 * Synopsis:
 *   #include "passwddb.h"
 *
 *  Search the file PWFILENAME for an username entry matching name.
 *  Similare to the library call getpwnam().
 *  On success it return a pointer to a struct local_passwd defined 
 *  in passwddb.h. The return structure is malloced inside the function.
 *  If it fails it returns NULL and pwdb_errno is set to
 *  PWDB_NOUSER if the user name could not be found,
 *  PWDB_FILEERR if it could not access the file,
 *  PWDB_MEMERR if it could not allocate memory for the struct pwdb_passwd,
 *  and PWDB_ENTRERR if the line in PWFILENAME somehow has invalide format. 
 *
 */
extern struct pwdb_passwd *pwdb_getpwnam(const char *name);


/*
 * FUNCTION:
 * int pwdb_update_user(struct pwdb_passwd *p)
 *
 * Synopsis:
 *  #include "passwddb.h"
 *
 * Search the file PWFILENAME for an entry matching the data in *p
 * If one is found, the entry is updated with the data in *p, otherwise
 * a new entry is created at the end of the file.
 * On success it returns 0.
 * If p==NULL it returns PWDB_NULL
 * If the file could not be accessed it returns PWDB_FILEERR
 * If memory could not be allocated it return PWDB_MEMERR
 */
extern int pwdb_update_user(struct pwdb_passwd *p);


/* 
 * FUNCTION:
 * const char *pwdb_err2str(int errno);
 *
 * Synopsis:
 * #include "pwdblib.h"
 *
 * Return a pointer to a const char string with a short error description
 * for errno
 *
 */
extern const char *pwdb_err2str(int errno);


#ifdef SUN
extern ssize_t getline(char **lineptr,size_t *n,FILE *stream);
extern char *strsep(char **stringp,const char *delim);
#endif
