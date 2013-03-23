#
#
# LIBFENC -- The Functional Encryption Library
#
#-------------------------------------------------------------------------------------------

dnl  Process this file with autoconf to produce a configure script.

define(FENC_COPYRIGHT,[[

FENC Copyright is blank for now.  Licensing information coming soon.

]])
AC_COPYRIGHT(FENC_COPYRIGHT)
AH_TOP(/*FENC_COPYRIGHT*/)


# We require at least autoconf version 2.5 to configure.
AC_PREREQ([2.59])
AC_INIT([fenc], [0.2.0], [libfenc-devel at googlegroups dot com])
AC_CONFIG_HEADERS([config.h])
# Identify source file in package directory that we can verify. 
AC_CONFIG_SRCDIR([libfenc_utils.c])
AC_PROG_LIBTOOL

# Set the default directory to /usr/. AC_PREFIX_DEFAULT([/usr/])
# Preparing for the automake.
# Useful information found here: 
#    http://www.gnu.org/software/hello/manual/automake/Public-Macros.html
# If you want to set specific options, check here:
#    http://www.gnu.org/software/hello/manual/automake/Options.html#Options
AM_INIT_AUTOMAKE
AM_MISSING_PROG([YACC], [bison -y])

# Useful information found here:
#    http://www.gnu.org/software/libtool/manual/html_node/Invoking-libtoolize.html
AC_CONFIG_MACRO_DIR([m4])


############################################################### 
# If macosx, than check for macports or fink default installation.

default_macports_path=/opt/local
default_fink_path=/sw
case $host_os in
     darwin*) 
              # Perhaps this will be useful some time.
     	      #dnl nested function support
     	      #AC_MSG_NOTICE([Adding -fnested-functions to CFLAGS])
	          #CFLAGS="-fnested-functions"

		 dnl fink or macports installation
     	      AC_MSG_CHECKING([for a fink or macports installation at $default_fink_path and $default_macports_path])
     	      if test -d $default_fink_path; then 
	      	 AC_MSG_RESULT([found fink!])
		 AC_MSG_NOTICE([Adding -I$default_fink_path/include to CPPFLAGS])
	      	 CPPFLAGS="-I$default_fink_path/include $CPPFLAGS"
		 AC_MSG_NOTICE([Adding -L$default_fink_path/lib to LDFLAGS])
		 LDFLAGS="-L$default_fink_path/lib $LDFLAGS"
              elif test -d $default_macports_path; then
		 AC_MSG_RESULT([found macports!])
		 AC_MSG_NOTICE([Adding -I$default_macports_path/include to CPPFLAGS])
	      	 CPPFLAGS="-I$default_macports_path/include $CPPFLAGS"
		 AC_MSG_NOTICE([Adding -L$default_macports_path/lib to LDFLAGS])
		 LDFLAGS="-L$default_macports_path/lib $LDFLAGS"
	      else
	 	 AC_MSG_RESULT(none)
		 AC_MSG_NOTICE([You may need to add set CPPFLAGS and LDFLAGS for gmp, etc.])
	      fi
	      ;;
esac
#
############################################################### 

############################################################### 
# Config for Windows DLLs.
# Framework for the below was extracted and
# modeled after the libgmp configure script.

AC_LIBTOOL_WIN32_DLL
AC_SUBST(LIBFENC_DLL,0)

case $host in
  *-*-cygwin* | *-*-mingw* | *-*-pw32* | *-*-os2*)
    # By default, build only static.
    if test -z "$enable_shared"; then
      enable_shared=no
    fi
    # Don't allow both static and DLL.
    if test "$enable_shared" != no && test "$enable_static" != no; then
      AC_MSG_ERROR([cannot build both static and DLL.
Use "--disable-static --enable-shared" to build just a DLL.])
    fi

    # "-no-undefined" is required when building a DLL, see documentation on
    # AC_LIBTOOL_WIN32_DLL.
    if test "$enable_shared" = yes; then
      FENC_LDFLAGS="$FENC_LDFLAGS -no-undefined -Wl,--export-all-symbols"
      LIBFENC_LDFLAGS="$LIBFENC_LDFLAGS -Wl,--output-def,.libs/libfenc.dll.def"
      LIBFENC_DLL=1
    fi
    ;;
esac
case $host in
  *-*-mingw*)
    gcc_cflags_optlist="$gcc_cflags_optlist nocygwin"
    gcc_cflags_nocygwin="-mno-cygwin"
    ;;
esac

AC_SUBST(FENC_LDFLAGS)
AC_SUBST(LIBFENC_LDFLAGS)
#
############################################################### 

# Checks for programs.
AC_PROG_YACC
AC_PROG_CC
AC_PROG_LEX

AC_ARG_VAR(ABI, Target CPU architecture for build: '32' '64' or default arch)

if test "$ABI" = "32"; then
	echo "building for 32-bit architecture ONLY!"
	CC="gcc -arch i386"
	CXX="g++ -arch i386"
elif test "$ABI" = "64"; then
	echo "building for 64-bit architecture ONLY!"
	CC="gcc -arch x86_64"
	CXX="g++ -arch x86_64"
else
	echo "building for default system architecture"
fi

# Checks for libraries.
# AC_CHECK_LIB (library, function, [action-if-found], [action-if-not-found], [other-libraries])
lib_err_msg="add its path to LDFLAGS\nsee ./configure --help"
AC_CHECK_LIB( [m], [pow], [],[
	      echo "************************"
	      echo "m library not found"
	      echo -e $lib_err_msg
	      echo "************************"
	      exit -1
	      ])
AC_CHECK_LIB( [gmp], [__gmpz_init], [],[
	      echo "************************"
	      echo "gmp library not found"
	      echo -e $lib_err_msg
	      echo "************************"
	      exit -1
	      ])
AC_CHECK_LIB( [crypto], [DES_xcbc_encrypt], [],[
              echo "************************"
              echo "OpenSSL library not found"
              echo -e $lib_err_msg
              echo "************************"
              exit -1
              ])
AC_CHECK_LIB( [pbc], [pbc_set_msg_to_stderr], [],[
	      echo "************************"
	      echo "pbc library not found"
	      echo -e $lib_err_msg
	      echo "************************"
	      exit -1
	      ])

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([libintl.h malloc.h stddef.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT64_T

dnl setup CFLAGS
# with_enable_optimized="yes"
AC_ARG_ENABLE( optimized, 
	       [AC_HELP_STRING([--enable-optimized],
			[Enables an optimized build [default=no]])],
         [with_enable_optimized="yes"],
	 [with_enable_optimized="no"])

CFLAGS="-Wall -W -Wfloat-equal -Wpointer-arith -Wcast-align -Wredundant-decls -Wendif-labels -Wshadow -pipe -ffast-math -U__STRICT_ANSI__"

if test "$with_enable_optimized" = "no"; then
   	CFLAGS="$CFLAGS -g -O2 -DDEBUG"
else
	CFLAGS="$CFLAGS -fomit-frame-pointer -O3"
fi

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset strchr strdup])

AC_CONFIG_FILES([Makefile tools/Makefile benchmark/Makefile])

# Always at the end, creates config.status.
AC_OUTPUT


# Print configuration to the user.
echo -ne "\n"
echo "global build variables"
echo "-----------------------------------------"
echo `date`
echo "host info:        $host"
echo "optimized build:  $with_enable_optimized"
echo "LDFLAGS:          $LDFLAGS"
echo "CPPFLAGS:         $CPPFLAGS"
echo "CFLAGS:           $CFLAGS"
echo "ABI:              $ABI"
#echo "CC:               $CC"
#echo "CXX:              $CXX"
echo "-----------------------------------------"
echo -ne "\n"

