# Process this file with autoconf to produce a configure script.
AC_INIT([PKI],[0.1],[Simon.Urbanek@r-project.org])
AC_CONFIG_SRCDIR([src/pki.h])
AC_CONFIG_HEADER([src/config.h])

# find R home and set CC/CFLAGS
: ${R_HOME=`R RHOME`}
if test -z "${R_HOME}"; then
  echo "could not determine R_HOME"
  exit 1
fi

CC=`${R_HOME}/bin/R CMD config CC`;
CXX=`${R_HOME}/bin/R CMD config CXX`;
CPPFLAGS="${CPPFLAGS} ${PKG_CPPFLAGS}"
CFLAGS=`${R_HOME}/bin/R CMD config CFLAGS`
CXXFLAGS=`${R_HOME}/bin/R CMD config CXXFLAGS`
LIBS="${LIBS} ${PKG_LIBS}"

AC_SUBST(R_HOME)

AC_ARG_VAR([OPENSSL_INCLUDES],[optional path to the include directory for OpenSSL headers])
AC_ARG_VAR([PKG_CPPFLAGS],[additional pre-processor flags])
AC_ARG_VAR([PKG_LIBS],[additional linker library flags])
if test "x${OPENSSL_INCLUDES}" != x; then
   CPPFLAGS="${CPPFLAGS} -I${OPENSSL_INCLUDES}"
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
  [AC_MSG_ERROR([Cannot find usable crypto library])])],
[AC_MSG_ERROR([Failed to find usable crypto library. Please install openssl-dev or equivalent and/or set PKG_LIBS if not in default location.])]
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
