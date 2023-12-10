
#ifndef CONFIG_H_INCLUDED
#define CONFIG_H_INCLUDED

//change PWD_LEN value in order to test different passwords length. You have to recompile the whole project after changing this value
#define PWD_LEN 7

//do not change these values
#define MAX_PWD_LEN 7
#define MD4_SIZE 16

#if PWD_LEN<3 || PWD_LEN > MAX_PWD_LEN
#error "Password length must be between 3 and 7"
#endif

#endif