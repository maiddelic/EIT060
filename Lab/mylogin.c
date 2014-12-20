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
#include "pwdblib.h" 

/* define some error constants */
#define NOUSER -1

/* define max size of a username */
#define USERNAME_SIZE 32
#define PASSWORD_SIZE 32




int read_username(char *username){

  printf("login: ");
  fgets(username,USERNAME_SIZE,stdin);

/* remove the CR included by getline() */
  username[strlen(username)-1]='\0'; 
  return(0);
}



int read_userpwd(char *username){
struct pwdb_passwd *pw_entry;
pw_entry = pwdb_getpwnam(username);
char *password;
char salt[2];
strncpy(salt, pw_entry->pw_passwd, 2);

password = getpass("password: "); 

/*if(pwdb_getpwnam(username)==NULL){
if(pwdb_errno==PWDB_NOUSER){
printf("user name could not be found.\n");	
}else if(pwdb_errno==PWDB_FILEERR){
printf("could not access the file.\n");}
else if(pwdb_errno==PWDB_MEMERR){
printf("could not allocate memory for the struct pwdb_passwd.\n");}
else if(pwdb_errno==PWDB_ENTRERR){
printf("line in PWFILENAME somehow has invalid format.\n");
}return(0);



}else{*/
if(strcmp(crypt(password, salt), pw_entry-> pw_passwd)==0){
printf("User authenticated successfully. \n");
pw_entry->pw_failed = 0;
pw_entry->pw_age++;
pwdb_update_user(pw_entry);
if(pw_entry->pw_age>=10){
printf("WOOPS, time to change PW. \n");
}
return(1);

}else{
if(pw_entry->pw_failed>=5){
printf("User locked. \n");
}
pw_entry->pw_failed++;
pwdb_update_user(pw_entry);
printf("Unknown user or incorrect password. \n");

read_username(username);

return(0);
}
}





int print_userinfo(const char *username){


struct pwdb_passwd *pw_entry;

pw_entry=pwdb_getpwnam(username);

if (pw_entry!=NULL) {
printf("\nInfo from getpwnam() for user: %s\n",username);
printf("Name: %s\n",pw_entry->pw_name);
printf("Passwd: %s\n",pw_entry->pw_passwd);
printf("Uid: %d\n",pw_entry->pw_uid);
printf("Gid: %d\n",pw_entry->pw_gid);
printf("Real name: %s\n",pw_entry->pw_gecos);
printf("Shell: %s\n\n",pw_entry->pw_shell);
} 
else return(NOUSER);

return(0);
}


int main(int argc,char **argv) {

char username[USERNAME_SIZE];
int count = 0;

/* write "login:" and read user input */



while(count==0){
read_username(username);
count = read_userpwd(username);	
}


/* Show user info from /etc/passwd */
if (print_userinfo(username)==NOUSER) {

printf("\nFound no user with name: %s\n",username); 
return(0);
}

return(0);
}