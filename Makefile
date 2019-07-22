# my_decoding/Makefile

MODULES = my_decoding
PGFILEDESC = "my_decoding - example of a logical decoding output plugin"

#REGRESS = test_filename
#REGRESS_OPTS = --temp-config ./logical.conf

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
