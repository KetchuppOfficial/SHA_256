CC = gcc
CFLAGS = -Wall -Wextra -Wshadow -Wfloat-equal -Wswitch-default

SRCDIR = ./src/
BUILDDIR = ./build/

SRC_LIST = sha_256.c
SRC = $(addprefix $(SRCDIR), $(SRC_LIST))

SUBS := $(SRC)
SUBS := $(subst $(SRCDIR), $(BUILDDIR), $(SUBS))

OBJ = $(SUBS:.c=.o)
DEPS = $(SUBS:.c=.d)

.PHONY: all

all: $(DEPS) $(OBJ)
	@ar r SHA_256.a $(OBJ)

$(BUILDDIR)%.o: $(SRCDIR)%.c
	@mkdir -p $(dir $@)
	@echo "Compiling \"$<\"..."
	@$(CC) $(CFLAGS) -c $< -o $@

include $(DEPS)

$(BUILDDIR)%.d: $(SRCDIR)%.c
	@echo "Collecting dependencies for \"$<\"..."
	@mkdir -p $(dir $@)
	@$(CC) -E $(CFLAGS) $< -MM -MT $(@:.d=.o) > $@
