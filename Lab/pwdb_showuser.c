/*
 * Program: pwdb_showuser.c
 *
 *  Depends on: pwdblib.c
 *
 *  If you compile this program on a SUN workstation, you must include
 *  the compande line option -DSUN to the gcc compiler.
 *
 * Synopsis:    
 *
 * Shows user info from local pwfile.
 *  
 * Usage:  pwdb_showuser username
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include "pwdblib.h"   /* include header declarations for pwdblib.c */



void print_info(struct pwdb_passwd *p){
   if (p!=NULL) {
    printf("Name: %s\n",p->pw_name);
    printf("Passwd: %s\n",p->pw_passwd);
    printf("Uid: %u\n",p->pw_uid);
    printf("Gid: %u\n",p->pw_gid);
    printf("Real name: %s\n",p->pw_gecos);
    printf("Shell: %s\n",p->pw_shell);
    printf("Failed: %u\n",p->pw_failed);
    printf("Age: %u\n",p->pw_age);
  } 
}


int main(int argc,char **argv){

  struct pwdb_passwd *p;

  if (argc<2) { 
    printf("Usage: pwdb_showuser username\n");
    return(0);
  }

  p=pwdb_getpwnam(argv[1]);

  if (p==NULL) {
    printf("pwdb_getpwnam returned error: %s\n",pwdb_err2str(pwdb_errno));
    return(0);
  }
  printf("User info:\n");
  print_info(p);
  
  return(0);
}
  

  
