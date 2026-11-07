AC_PREREQ([2.69])
AC_INIT([wsl-dns-forward], [1.1.0], [david@clearbrookdistillery.com], [wsl-dns-forward],
        [https://github.com/moebiusV/wsl-dns-forward])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([gnu -Wall -Werror subdir-objects])

AC_PROG_CC
AC_PROG_INSTALL
AC_USE_SYSTEM_EXTENSIONS
AC_CHECK_HEADERS([arpa/inet.h poll.h pwd.h grp.h sys/wait.h], [], [AC_MSG_ERROR([a POSIX system is required])])
AC_CHECK_FUNCS([accept4 pipe2 setgroups fsync], [], [AC_MSG_ERROR([a Linux-style libc is required])])

dnl Where powershell.exe lives, as seen from inside WSL.
AC_ARG_WITH([powershell],
  [AS_HELP_STRING([--with-powershell=PATH], [path to powershell.exe inside WSL])],
  [powershell=$withval],
  [powershell=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe])
AC_DEFINE_UNQUOTED([POWERSHELL_PATH], ["$powershell"], [Path to powershell.exe])

dnl Optional systemd unit (WSL distros with systemd=true).
AC_ARG_WITH([systemdsystemunitdir],
  [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [install wsl-dns-forward.service here])],
  [systemdunitpath=$withval], [systemdunitpath=no])
AC_SUBST([systemdunitpath])
AM_CONDITIONAL([HAVE_SYSTEMD_UNIT], [test "x$systemdunitpath" != xno])

dnl Compiler hardening and warnings, kept apart from the user's CFLAGS.
AC_DEFUN([WMF_TRY_FLAG], [
  AC_MSG_CHECKING([whether $CC accepts $2])
  wmf_save_CFLAGS=$CFLAGS; wmf_save_LDFLAGS=$LDFLAGS
  CFLAGS="$CFLAGS $2 -Werror"; LDFLAGS="$LDFLAGS $3"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])],
    [AC_MSG_RESULT([yes]); $1="$$1 $2"; $1_LD="$$1_LD $3"], [AC_MSG_RESULT([no])])
  CFLAGS=$wmf_save_CFLAGS; LDFLAGS=$wmf_save_LDFLAGS
])
HARDEN_CFLAGS=; HARDEN_CFLAGS_LD=; WARN_CFLAGS=; WARN_CFLAGS_LD=
WMF_TRY_FLAG([WARN_CFLAGS], [-Wall], [])
WMF_TRY_FLAG([WARN_CFLAGS], [-Wextra], [])
WMF_TRY_FLAG([WARN_CFLAGS], [-Wshadow], [])
WMF_TRY_FLAG([WARN_CFLAGS], [-Wformat=2], [])
WMF_TRY_FLAG([WARN_CFLAGS], [-Wconversion], [])
WMF_TRY_FLAG([HARDEN_CFLAGS], [-fstack-protector-strong], [])
WMF_TRY_FLAG([HARDEN_CFLAGS], [-fPIE], [-pie])
WMF_TRY_FLAG([HARDEN_CFLAGS], [-Wformat-security], [])
WMF_TRY_FLAG([HARDEN_CFLAGS], [-fno-strict-overflow], [])
WMF_TRY_FLAG([HARDEN_CFLAGS], [], [-Wl,-z,relro,-z,now])
HARDEN_LDFLAGS=$HARDEN_CFLAGS_LD
AC_SUBST([HARDEN_CFLAGS]) AC_SUBST([HARDEN_LDFLAGS]) AC_SUBST([WARN_CFLAGS])
dnl _FORTIFY_SOURCE needs optimisation, is pointless under the sanitizers, and is left alone when the
dnl compiler or the distribution's flags already set it.
FORTIFY_CPPFLAGS=
case "$CFLAGS" in
  *-O[[123s]]*)
    AC_MSG_CHECKING([whether _FORTIFY_SOURCE is already set])
    if echo "$CPPFLAGS $CFLAGS" | grep -q _FORTIFY_SOURCE ||
       echo | $CC $CPPFLAGS $CFLAGS -dM -E - 2>/dev/null | grep -q '_FORTIFY_SOURCE'; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no, adding -D_FORTIFY_SOURCE=2])
      FORTIFY_CPPFLAGS="-D_FORTIFY_SOURCE=2"
    fi ;;
esac

AC_ARG_ENABLE([sanitizers],
  [AS_HELP_STRING([--enable-sanitizers], [build with AddressSanitizer and UBSan (for testing)])],
  [], [enable_sanitizers=no])
SAN_CFLAGS=
AS_IF([test "x$enable_sanitizers" = xyes],
  [FORTIFY_CPPFLAGS=
   SAN_CFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g"
   AC_MSG_NOTICE([sanitizers enabled])])
AC_SUBST([SAN_CFLAGS])
AC_SUBST([FORTIFY_CPPFLAGS])

AC_ARG_ENABLE([fuzzers],
  [AS_HELP_STRING([--enable-fuzzers], [build libFuzzer targets (needs clang)])],
  [], [enable_fuzzers=no])
FUZZ_CFLAGS="-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined -g -O1"
AS_IF([test "x$enable_fuzzers" = xyes], [
  wmf_save_CFLAGS=$CFLAGS; CFLAGS="$CFLAGS $FUZZ_CFLAGS"
  AC_LINK_IFELSE([AC_LANG_SOURCE([[#include <stdint.h>
#include <stddef.h>
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { (void)d; (void)n; return 0; }]])],
    [], [AC_MSG_ERROR([--enable-fuzzers needs clang with libFuzzer; try CC=clang])])
  CFLAGS=$wmf_save_CFLAGS])
AC_SUBST([FUZZ_CFLAGS])
AM_CONDITIONAL([ENABLE_FUZZERS], [test "x$enable_fuzzers" = xyes])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
