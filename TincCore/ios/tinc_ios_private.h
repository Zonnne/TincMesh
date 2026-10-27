/*
    tinc_ios_private.h -- shared state between the tinc_ios glue files
*/

#ifndef TINC_IOS_PRIVATE_H
#define TINC_IOS_PRIVATE_H

/* tinc's end of the packet socketpair, handed over by tinc_ios_run().
   ios_device.c takes ownership (and resets this to -1) when it opens the device. */
extern int tinc_ios_tun_fd;

/* Packet I/O for the policy engine, provided by ios_device.c. */
struct policy_io_t;
extern const struct policy_io_t tinc_ios_policy_io;

#endif
