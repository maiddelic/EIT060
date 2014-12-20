/*
 * Program userinfo.c
 * 
 * This program prompts the user for a login name, and tries to 
 * extract user information from the /etc/passwd file.
 *
 */

#define _XOPEN_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <string.h>

/* define some error constants */
#define NOUSER -1

/* define max size of a username */
#define USERNAME_SIZE 32




int read_username(char *username){

  printf("login: ");
  fgets(username,USERNAME_SIZE,stdin);

 /* remove the CR included by getline() */
  username[strlen(username)-1]='\0';  
  return(0);
}




int print_userinfo(const char *username){
  struct passwd *pw_entry;

  pw_entry=getpwnam(username);
  if (pw_entry!=NULL) {
    printf("\nInfo from getpwnam() for user: %s\n",username);
    printf("Name: %s\n",pw_entry->pw_name);
    printf("Passwd: %s\n",pw_entry->pw_passwd);
    printf("Uid: %d\n",pw_entry->pw_uid);
    printf("Gid: %d\n",pw_entry->pw_gid);
    printf("Real name: %s\n",pw_entry->pw_gecos);
    printf("Home dir: %s\n",pw_entry->pw_dir);
    printf("Shell: %s\n\n",pw_entry->pw_shell);
  } 
  else return(NOUSER);
 
  return(0);
}


int main(int argc,char **argv) {
  char username[USERNAME_SIZE];

  /* write "login:" and read user input */
  read_username(username);

  /* Show user info from /etc/passwd */
  if (print_userinfo(username)==NOUSER) {
      /* if there are no user with that usename... */
      printf("\nFound no user with name: %s\n",username);   
      return(0);
  }

  return(0);
}
