include ../../../system/include.mk

PRIV_FILES=../priv/epam

CFLAGS += -I${ERL_INTERFACE_INCLUDE}
LDFLAGS +=  ${ERL_INTERFACE_LIBS} -lpthread -lpam

all: $(PRIV_FILES)

clean:
	sudo rm -f $(PRIV_FILES)
	rm -f epam.o

../priv/epam:	epam.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)
	sudo chown root $@
	sudo chmod 4755 $@
