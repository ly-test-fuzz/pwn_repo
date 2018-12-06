CC = gcc
NAME = bin_waf

$(NAME): main.o waf.o log.o util.o 
	$(CC) -o $(NAME) -no-pie  main.o waf.o  log.o util.o -lpthread

main.o: main.c
	$(CC) -o main.o -c -no-pie main.c

waf.o: waf.c waf.h
	$(CC) -o waf.o -c -no-pie -lpthread waf.c

log.o: log.c log.h
	$(CC) -o log.o -c -no-pie log.c

util.o: util.c util.h
	$(CC) -o util.o -c -no-pie util.c
 
clean:
	rm *.o

