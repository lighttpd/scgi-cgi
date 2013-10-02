Description
-----------

:Homepage:
    http://redmine.lighttpd.net/projects/scgi-cgi/wiki

scgi-cgi is a SCGI application to run normal cgi applications. It doesn't
make CGI applications faster, but it allows you to run them on a different
host and with different user permissions (without the need for suexec).

scgi-cgi is released under the `MIT license <http://git.lighttpd.net/scgi-cgi.git/tree/COPYING>`_

Usage
-----

Examples for spawning a scgi-cgi instance with daemontools or runit::

  #!/bin/sh
  # run script

  exec spawn-scgi -n -s /var/run/scgi-cgi.sock -u www-default -U www-data -- /usr/bin/scgi-cgi


Build dependencies
------------------

* libevent (http://libevent.org/)
* cmake or autotools (for snapshots/releases the autotool generated files are included)


Build
-----

* snapshot/release with autotools::

   ./configure
   make

* build from git: ``git clone git://git.lighttpd.net/scgi-cgi.git``

 * with autotools::

    ./autogen.sh
    ./configure
    make

 * with cmake (should work with snapshots/releases too)::

    cmake .
    make
