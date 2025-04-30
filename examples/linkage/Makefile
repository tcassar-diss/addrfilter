CXX      := gcc
CFLAGS   := -O0 -Wall -g -fno-inline-small-functions 
PICFLAGS := -fPIC
LDFLAGS  := -Wl,-rpath,'$$ORIGIN'
LIBDIR   := .

# Modules
MODS     := getpid printf
LIBS     := $(patsubst %,lib%.so,$(MODS))
HDRS     := $(addsuffix .h,$(MODS))

# Main
SRCS     := main.c
OBJS     := $(SRCS:.c=.o)
TARGET   := linked

.PHONY: all clean

all: $(LIBS) $(TARGET)

# Shared-library rule
lib%.so: %.c %.h
	$(CXX) $(PICFLAGS) $(CFLAGS) -shared -o $@ $<

# Main object
main.o: main.c $(HDRS)
	$(CXX) $(CFLAGS) -c $< -o $@

# Link
$(TARGET): $(OBJS) $(LIBS)
	$(CXX) $(CFLAGS) -o $@ $(OBJS) \
	        -L$(LIBDIR) $(patsubst %, -l%,$(MODS)) \
	        $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET) $(LIBS) *.toml
