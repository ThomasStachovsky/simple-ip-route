CXX = g++
CPPFLAGS = -std=c++11 -Wall -Wextra

all: router
router: main.o router.o error.o
	g++ $(CPPFLAGS) -o router $^
main.o: router.h
router.o: router.h error.h
error.o: error.h

clean:
	rm -f *.o
distclean:
	rm -f *.o
	rm -f router

