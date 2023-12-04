#ifndef CONFIG_H_INCLUDED
#define CONFIG_H_INCLUDED

#define PWD_LEN 6
#define MAX_PWD_LEN 7
#define MD4_SIZE 16

#if PWD_LEN<1 || PWD_LEN > MAX_PWD_LEN
#error "Password length must be between 1 and 7"
#endif

#endif