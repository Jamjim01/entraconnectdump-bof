CFLAGS = -c -Os -mno-stack-arg-probe -fno-asynchronous-unwind-tables -fno-ident \
         -Wno-int-conversion -Wno-discarded-qualifiers -Wno-incompatible-pointer-types

CC64 = x86_64-w64-mingw32-gcc
CC32 = i686-w64-mingw32-gcc
STRIP = strip --strip-unneeded

SOURCES = entrasyncdump_version entrasyncdump_dumpcertinfo entrasyncdump_dumpcert entrasyncdump_autodumpcert entrasyncdump_dumpcreds

all: $(addsuffix .x64.o,$(SOURCES)) $(addsuffix .x86.o,$(SOURCES))

%.x64.o: %.c entrasyncdump_common.h
	$(CC64) $(CFLAGS) $< -o $@
	$(STRIP) $@

%.x86.o: %.c entrasyncdump_common.h
	$(CC32) $(CFLAGS) $< -o $@
	$(STRIP) $@

verbose: $(addsuffix _verbose,$(SOURCES))

%_verbose: %.c entrasyncdump_common.h
	$(CC64) $(CFLAGS) -DVERBOSE $< -o $(basename $<).x64.o
	$(STRIP) $(basename $<).x64.o
	$(CC32) $(CFLAGS) -DVERBOSE $< -o $(basename $<).x86.o
	$(STRIP) $(basename $<).x86.o

# Legacy monolith (kept for backwards compat)
legacy: entrasyncdump.x64.o entrasyncdump.x86.o

entrasyncdump.x64.o: entrasyncdump.c
	$(CC64) $(CFLAGS) entrasyncdump.c -o entrasyncdump.x64.o
	$(STRIP) entrasyncdump.x64.o

entrasyncdump.x86.o: entrasyncdump.c
	$(CC32) $(CFLAGS) entrasyncdump.c -o entrasyncdump.x86.o
	$(STRIP) entrasyncdump.x86.o

clean:
	rm -f *.x64.o *.x86.o
