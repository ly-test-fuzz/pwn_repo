#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"

// mode 1 全文匹配(先trim 过滤空格 后检测)
// mode 2 部分匹配(粗暴匹配) 
// mode 3 参数命令匹配(检测 加空格 , tab )
//  
// mode_1  "1"  1
// mode_2  "2"  2
// mode_3  "3" 3
// mode_13 "13" 4


int find_str(char *dest , check find_word_list[] , int check_turn ){
	char temp[30];
	char command[30];
	int mode;

	for(int i = 0 ; i < check_turn ; i++ ){
		strcpy(command , find_word_list[i].command);
		mode = find_word_list[i].mode;	
		if(mode == mode_1){
			if(find_1(dest , command))
				return true;
		}else if(mode == mode_2){
			if(find_2(dest , command))
				return true;
		}else if(mode == mode_3){
			if(find_3(dest , command))
				return true;
		}else if(mode == mode_13){
			if(find_1(dest , command))
				return true;
			if(find_3(dest , command))
				return true;
		}
	}	
	return false;
}

char *strnstr(char *s1,char *s2,int pos1)
{
    int l1,l2;

    l2=strlen(s2);
    if(!l2)
        return(char*)s1;
    l1=strlen(s1);
    pos1=(pos1>l1)?l1:pos1;
    while(pos1>=l2){
        pos1--;
        if(!memcmp(s1,s2,l2))
            return(char*)s1;
        s1++;
    }
    return NULL;
}

void trim(char *sou){
	int sou_index = 0 , result_index = 0;
	while(sou[result_index]){
		if(sou[sou_index] != ' '){
		     sou[result_index] = sou[sou_index];
		     sou_index++;
		     result_index++;
		}else{
			sou_index++;
		}
	}
}

int find_1(char *dest , char *command){
	char temp[20];
	strcpy(temp , dest);
	trim(temp);
	if(!strcmp(temp , command))// 0 - equal - find
		return true;
	return false;
}

int find_2(char *dest , char *command){
	if(strstr(dest , command)) // addr - true -  find  
		return true;
	return false;
}

int find_3(char *dest , char *command){
	char temp[20];
	strcpy(temp , command);
	strcat(temp , " ");
	if(strstr(dest , temp)) // addr - true -  find  
		return true;
	return false;
}