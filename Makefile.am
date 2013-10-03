EXTRA_DIST=autogen.sh CMakeLists.txt cmake config.h.cmake scgi-cgi.1 README.rst
man1_MANS=scgi-cgi.1

AM_CFLAGS=$(LIBEVENT_CFLAGS)
scgi_cgi_LDADD=$(LIBEVENT_LIBS)

bin_PROGRAMS=scgi-cgi
scgi_cgi_SOURCES=scgi-cgi.c
