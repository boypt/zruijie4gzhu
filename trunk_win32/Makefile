# Project: zRuijie4GZHU
# Makefile created by Dev-C++ 4.9.9.2

CPP  = i486-mingw32-g++
CC   = i486-mingw32-gcc
WINDRES = i486-mingw32-windres
RES  = zRuijie4GZHU_private.res
OBJ  = win_main.o blog.o eap_protocol.o md5.o zruijie.o $(RES)
LINKOBJ  = win_main.o blog.o eap_protocol.o md5.o zruijie.o $(RES)
LIBS =  -L"/usr/i486-mingw32/lib" -L"WpdPack/Lib" -mwindows -lcomctl32 -lwpcap -lws2_32 -liphlpapi  
INCS =  -I"/usr/i486-mingw32/include"  -I"WpdPack/Include"
CXXINCS = 
BIN  = zRuijie4GZHU.exe
CXXFLAGS = $(CXXINCS)   -fexpensive-optimizations -O2
CFLAGS = $(INCS)  -Wall -O1
RM = rm -f

.PHONY: all all-before all-after clean clean-custom

all: all-before zRuijie4GZHU.exe all-after


clean: clean-custom
	${RM} $(OBJ) $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LINKOBJ) -o "zRuijie4GZHU.exe" $(LIBS)

win_main.o: win_main.c
	$(CC) -c win_main.c -o win_main.o $(CFLAGS)

blog.o: blog.c
	$(CC) -c blog.c -o blog.o $(CFLAGS)

eap_protocol.o: eap_protocol.c
	$(CC) -c eap_protocol.c -o eap_protocol.o $(CFLAGS)

md5.o: md5.c
	$(CC) -c md5.c -o md5.o $(CFLAGS)

zruijie.o: zruijie.c
	$(CC) -c zruijie.c -o zruijie.o $(CFLAGS)

zRuijie4GZHU_private.res: zRuijie4GZHU_private.rc 
	$(WINDRES) -i zRuijie4GZHU_private.rc --input-format=rc -o zRuijie4GZHU_private.res -O coff 
