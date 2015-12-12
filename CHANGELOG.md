# Changes in version 1.x.x - 201x-xx-xx

 * Medium changes
   - Parse flag thresholds in bridge network statuses, and parse the
     "ignoring-advertised-bws" flag threshold in relay network status
     votes.
   - Support parsing of .xz-compressed tarballs using Apache Commons
     Compress and XZ for Java.  Applications only need to add XZ for
     Java as dependency if they want to parse .xz-compressed tarballs.
   - Introduce a new ExitList.Entry type for exit list entries instead
     of the ExitListEntry type which is now deprecated.  The main
     difference between the two is that ExitList.Entry can hold more
     than one exit address and scan time which were previously parsed
     as multiple ExitListEntry instances.


# Changes in version 1.0.0 - 2015-12-05

 * Major changes
   - This is the initial release after four years of development.
     Happy 4th birthday!

