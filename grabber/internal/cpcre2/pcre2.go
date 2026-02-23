// Package cpcre2 provides a thin Go wrapper around the PCRE2 C library,
// embedded as source for cross-platform CGO compilation.
package cpcre2

/*
#cgo CFLAGS: -I${SRCDIR}/csrc -DHAVE_CONFIG_H -DPCRE2_CODE_UNIT_WIDTH=8 -DPCRE2_STATIC
#include "pcre2.h"
#include <stdlib.h>

// Wrapper to avoid CGo typedef issues with PCRE2_SPTR8
static pcre2_code* wrap_compile(const char *pattern, uint32_t options, int *errcode, PCRE2_SIZE *erroffset) {
	return pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED, options, errcode, erroffset, NULL);
}

static int wrap_match(pcre2_code *code, const char *subject, size_t length,
                      pcre2_match_data *match_data) {
	return pcre2_match(code, (PCRE2_SPTR)subject, (PCRE2_SIZE)length, 0, 0, match_data, NULL);
}

static int wrap_get_error_message(int errcode, char *buf, size_t buflen) {
	return pcre2_get_error_message(errcode, (PCRE2_UCHAR *)buf, (PCRE2_SIZE)buflen);
}
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// CompileOption represents PCRE2 compile-time options.
type CompileOption uint32

const (
	Caseless CompileOption = C.PCRE2_CASELESS
	DotAll   CompileOption = C.PCRE2_DOTALL
)

// Regexp represents a compiled PCRE2 regular expression.
type Regexp struct {
	code      *C.pcre2_code
	matchData *C.pcre2_match_data
}

// Compile compiles a PCRE2 pattern with no options.
func Compile(pattern string) (*Regexp, error) {
	return CompileOpts(pattern, 0)
}

// CompileOpts compiles a PCRE2 pattern with the given options.
func CompileOpts(pattern string, opts CompileOption) (*Regexp, error) {
	cpattern := C.CString(pattern)
	defer C.free(unsafe.Pointer(cpattern))

	var errcode C.int
	var erroffset C.PCRE2_SIZE

	code := C.wrap_compile(cpattern, C.uint32_t(opts), &errcode, &erroffset)
	if code == nil {
		buf := make([]byte, 256)
		C.wrap_get_error_message(errcode, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
		return nil, fmt.Errorf("pcre2 compile error at offset %d: %s", erroffset, string(buf[:cstrlen(buf)]))
	}

	matchData := C.pcre2_match_data_create_from_pattern(code, nil)
	if matchData == nil {
		C.pcre2_code_free(code)
		return nil, fmt.Errorf("pcre2: failed to create match data")
	}

	re := &Regexp{code: code, matchData: matchData}
	runtime.SetFinalizer(re, (*Regexp).Close)
	return re, nil
}

// Close frees the compiled pattern and match data.
func (re *Regexp) Close() {
	if re.matchData != nil {
		C.pcre2_match_data_free(re.matchData)
		re.matchData = nil
	}
	if re.code != nil {
		C.pcre2_code_free(re.code)
		re.code = nil
	}
}

// MatchString returns true if the pattern matches the string.
func (re *Regexp) MatchString(s string) bool {
	var cstr *C.char
	slen := len(s)
	if slen == 0 {
		cstr = (*C.char)(unsafe.Pointer(&[]byte{0}[0]))
	} else {
		cstr = (*C.char)(unsafe.Pointer(unsafe.StringData(s)))
	}
	rc := C.wrap_match(re.code, cstr, C.size_t(slen), re.matchData)
	return rc >= 0
}

// FindStringSubmatch returns a slice of strings holding the text of the
// leftmost match and the matches of each capture group, or nil if no match.
func (re *Regexp) FindStringSubmatch(s string) []string {
	var cstr *C.char
	slen := len(s)
	if slen == 0 {
		cstr = (*C.char)(unsafe.Pointer(&[]byte{0}[0]))
	} else {
		cstr = (*C.char)(unsafe.Pointer(unsafe.StringData(s)))
	}

	rc := C.wrap_match(re.code, cstr, C.size_t(slen), re.matchData)
	if rc < 0 {
		return nil
	}

	ovecCount := int(C.pcre2_get_ovector_count(re.matchData))
	ovecPtr := C.pcre2_get_ovector_pointer(re.matchData)
	ovecSlice := unsafe.Slice((*C.size_t)(unsafe.Pointer(ovecPtr)), ovecCount*2)

	result := make([]string, ovecCount)
	for i := 0; i < ovecCount; i++ {
		start := ovecSlice[2*i]
		end := ovecSlice[2*i+1]
		// PCRE2_UNSET = ~(PCRE2_SIZE)0
		if start == ^C.size_t(0) {
			result[i] = ""
			continue
		}
		result[i] = s[start:end]
	}
	return result
}

func cstrlen(b []byte) int {
	for i, v := range b {
		if v == 0 {
			return i
		}
	}
	return len(b)
}
