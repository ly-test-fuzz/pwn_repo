#include <stdio.h>
#define true 1
#define false !true
#define mode_1 1
#define mode_2 2
#define mode_3 3
#define mode_13 4

typedef struct {
	const char *command;
	int mode;
} check;

int find_str(char *dest , check find_word_list[] , int check_turn );
char *strnstr(char *s1,char *s2,int pos1);
void trim(char *sou);
int find_1(char *dest , char *command);
int find_2(char *dest , char *command);
int find_3(char *dest , char *command);