include ../../../system/include.mk

include ../vsn.mk
VSN=$(EPAM_VSN)

MODULES= epam_app	\
	epam_sup	\
	epam

EBIN_FILES=$(MODULES:%=../ebin/%.$(EMULATOR)) ../ebin/epam.app
ERLC_FLAGS+=-I../include -I. -I../..

#
# Targets
#

all: $(EBIN_FILES) 

debug:
	$(MAKE) ERLC_FLAGS+="$(ERLC_FLAGS) +debug_info -Ddebug"

clean:
	rm -f $(EBIN_FILES)
