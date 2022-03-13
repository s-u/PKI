# Process this file with autoconf to produce a configure script.
AC_INIT([PKI],[0.1],[Simon.Urbanek@r-project.org])
AC_CONFIG_SRCDIR([src/pki.h])
AC_CONFIG_HEADERS([src/config.h])

# find R home and set CC/CFLAGS
: ${R_HOME=`R RHOME`}
if test -z "${R_HOME}"; then
  echo "could not determine R_HOME"
  exit 1
fi

RBIN="${R_HOME}/bin/R"

# pick all flags for testing from R
: ${CC=`"${RBIN}" CMD config CC`}
: ${CFLAGS=`"${RBIN}" CMD config CFLAGS`}
: ${CPPFLAGS=`"${RBIN}" CMD config CPPFLAGS`}
: ${LDFLAGS=`"${RBIN}" CMD config LDFLAGS`}
: ${CPP="$CC -E"}
: ${PKGCONFIG=pkg-config}

# honor PKG_xx overrides
LIBS="${LIBS} ${PKG_LIBS}"
# for CPPFLAGS we will superfluously double R's flags
# since we'll set PKG_CPPFLAGS with this, but that shouldn't hurt
CPPFLAGS="${CPPFLAGS} ${PKG_CPPFLAGS}"

AC_SUBST(R_HOME)

AC_ARG_VAR([OPENSSL_INCLUDES],[optional path to the include directory for OpenSSL headers])
AC_ARG_VAR([PKG_CPPFLAGS],[additional pre-processor flags])
AC_ARG_VAR([PKG_LIBS],[additional linker library flags])
AC_ARG_VAR([PKGCONFIG],[command to use for flags detection if none are supplied, defaults to pkg-config])

if test "x${OPENSSL_INCLUDES}" != x; then
   CPPFLAGS="${CPPFLAGS} -I${OPENSSL_INCLUDES}"
else
   if test x"${PKG_CPPFLAGS}" = x -a x"${PKG_LIBS}" = x -a x"$PKGCONFIG" != x; then
      AC_MSG_CHECKING([for $PKGCONFIG])
      if $PKGCONFIG --version >/dev/null 2>&1; then
         AC_MSG_RESULT(yes)
         AC_MSG_CHECKING([whether it knows about openssl])
         if $PKGCONFIG openssl; then
            AC_MSG_RESULT(yes)
	    PC_CFLAGS=`$PKGCONFIG --cflags openssl`
	    PC_LIBS=`$PKGCONFIG --libs openssl`
	    AC_MSG_NOTICE([CFLAGS: ${PC_CFLAGS}])
	    AC_MSG_NOTICE([LIBS: ${PC_LIBS}])
	    CPPFLAGS="${CPPFLAGS} ${PC_CFLAGS}"
	    LIBS="${LIBS} ${PC_LIBS}"
	 else
	    AC_MSG_RESULT(no)
	 fi
      else
         AC_MSG_RESULT(no)
      fi
   fi
fi

# Checks for programs.
AC_PROG_CC

AC_CHECK_HEADER([openssl/ssl.h],,[
  if test "`uname -s`" = Darwin; then
     AC_MSG_NOTICE([Missing OpenSSL headers on macOS,])
     AC_MSG_NOTICE([attempting to get headers from Apple...])
     mkdir tmp
     cd tmp
     curl -L https://opensource.apple.com/tarballs/OpenSSL098/OpenSSL098-59.tar.gz | tar fxz -
     if test -e OpenSSL098-59/src/include/openssl; then
        mkdir ../src/include
        mv OpenSSL098-59/src/include/openssl ../src/include
     else
        AC_MSG_ERROR([Failed to download OpenSSL sources from Apple. Please install OpenSSL headers before installing PKI.])
     fi
     cd ..
     rm -rf tmp
     CPPFLAGS="-Iinclude -Isrc/include ${CPPFLAGS}"
     AS_UNSET([ac_cv_header_openssl_ssl_h])
     AC_CHECK_HEADER([openssl/ssl.h],,[AC_MSG_ERROR([Failed to find usable OpenSSL headers])])
  fi
])

# check RSA/crypto
AC_CHECK_HEADER([openssl/rsa.h],
[AC_SEARCH_LIBS(RSA_generate_key_ex, [crypto ssl openssl],,
  [ works=no
    ## more Darwin woes - Catalina SDK removes crypto, so we have to force
    ## the .dylib itself from the system since -l only searches in the SDK
    if test "`uname -s`" = Darwin; then
      AC_MSG_NOTICE([Regular linking failed, trying force-link crypto from system location:])
      for lib in /usr/lib/libcrypto.dylib; do
        save_LIBS="$LIBS"
        LIBS="$LIBS $lib"
	AC_LINK_IFELSE([AC_LANG_FUNC_LINK_TRY(RSA_generate_key_ex)], [works=yes], [LIBS="${save_LIBS}"])
	if test $works = yes; then
	   AC_MSG_NOTICE([Found working library: $lib])
	   break;
	fi
      done
    fi
    if test "$works" = no; then
      AC_MSG_ERROR([Cannot find usable crypto library. Please install openssl-dev or equivalent and/or set PKG_LIBS if not in default location.])
    fi
  ])],
[AC_MSG_ERROR([Failed to find usable ssl headers. Please install openssl-dev or equivalent and/or set PKG_LIBS/PKG_CPPFLAGS if not in default location.])]
)

# check SSL support
AC_CHECK_HEADER([openssl/ssl.h],
[AC_SEARCH_LIBS(SSL_CTX_load_verify_locations, [ssl openssl],,
  [AC_MSG_ERROR([Cannot find usable SSL library])])],
[AC_MSG_ERROR([Failed to find usable SSL library. Please install openssl-dev or equivalent and/or set PKG_LIBS if not in default location.])]
)

AC_SUBST(LIBS)
AC_SUBST(CPPFLAGS)

AC_CONFIG_FILES([src/Makevars])
AC_OUTPUT
