// Single compilation unit that includes all PCRE2 source files.
// CGo only compiles .c files in the package directory, so we use this
// to pull in the sources from the csrc/ subdirectory.

// These are already defined via CGo CFLAGS in pcre2.go:
// HAVE_CONFIG_H, PCRE2_CODE_UNIT_WIDTH=8, PCRE2_STATIC

#include "csrc/pcre2_chartables.c"
#include "csrc/pcre2_auto_possess.c"
#include "csrc/pcre2_chkdint.c"
#include "csrc/pcre2_compile.c"
#include "csrc/pcre2_compile_cgroup.c"
#include "csrc/pcre2_compile_class.c"
#include "csrc/pcre2_config.c"
#include "csrc/pcre2_context.c"
#include "csrc/pcre2_convert.c"
#include "csrc/pcre2_dfa_match.c"
#include "csrc/pcre2_error.c"
#include "csrc/pcre2_extuni.c"
#include "csrc/pcre2_find_bracket.c"
#include "csrc/pcre2_maketables.c"
#include "csrc/pcre2_match.c"
#include "csrc/pcre2_match_data.c"
#include "csrc/pcre2_match_next.c"
#include "csrc/pcre2_newline.c"
#include "csrc/pcre2_ord2utf.c"
#include "csrc/pcre2_pattern_info.c"
#include "csrc/pcre2_script_run.c"
#include "csrc/pcre2_serialize.c"
#include "csrc/pcre2_string_utils.c"
#include "csrc/pcre2_study.c"
#include "csrc/pcre2_substitute.c"
#include "csrc/pcre2_substring.c"
#include "csrc/pcre2_tables.c"
#include "csrc/pcre2_ucd.c"
#include "csrc/pcre2_valid_utf.c"
#include "csrc/pcre2_xclass.c"
