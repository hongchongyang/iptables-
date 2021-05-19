main:main.o assign.o deduplicate.o merge.o
	gcc main.o assign.o deduplicate.o merge.o -o main -lip4tc
main.o:main.c assign.c deduplicate.c merge.c
	gcc -c main.c -lip4tc
assign.o:assign.c
	gcc -c assign.c -lip4tc
deduplicate.o:deduplicate.c
	gcc -c deduplicate.c
merge.o:merge.c
	gcc -c merge.c
clean:
	rm -f main *.o
