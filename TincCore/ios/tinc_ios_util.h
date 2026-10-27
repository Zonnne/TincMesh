/*
    tinc_ios_util.h -- helpers shared by the tinc_ios glue files
*/

#ifndef TINC_IOS_UTIL_H
#define TINC_IOS_UTIL_H

/* Opens tinc's random source once per process. tinc_ios_run() manages
   its own crypto_init()/crypto_exit(), so this is for the app process. */
extern void tinc_ios_crypto_init(void);

/* Returns a malloc()ed JSON string literal (with quotes) for s; NULL becomes "". */
extern char *tinc_ios_json_quote(const char *s);

#endif
