include ../../../system/include.mk

PRIV_FILES=../priv/epam

CFLAGS += -I${ERL_INTERFACE_INCLUDE}
LDFLAGS +=  ${ERL_INTERFACE_LIBS} -lpthread -lpam -lpam_misc

all: $(PRIV_FILES) epam_new

clean:
	sudo rm -f $(PRIV_FILES)
	rm -f epam.o
	rm -f epam_new

../priv/epam:	epam.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)
	sudo chown root $@
	sudo chmod 4755 $@

epam_new: epam_new.c
	$(CC) -g -o $@ $< $(CFLAGS) $(LDFLAGS)
	sudo chown root $@
	sudo chmod 4755 $@
