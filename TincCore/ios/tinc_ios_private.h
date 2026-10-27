/*
    tinc_ios_private.h -- shared state between the tinc_ios glue files
*/

#ifndef TINC_IOS_PRIVATE_H
#define TINC_IOS_PRIVATE_H

/* tinc's end of the packet socketpair, handed over by tinc_ios_run().
   ios_device.c takes ownership (and resets this to -1) when it opens the device. */
extern int tinc_ios_tun_fd;

#endif
