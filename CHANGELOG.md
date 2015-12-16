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
   - Introduce four new types to distinguish between relay and bridge
     descriptors: RelayServerDescriptor, RelayExtraInfoDescriptor,
     BridgeServerDescriptor, and BridgeExtraInfoDescriptor.  The
     existing types, ServerDescriptor and ExtraInfoDescriptor, are
     still usable and will not be deprecated, because applications may
     not care whether a relay or a bridge published a descriptor.
   - Support Ed25519 certificates, Ed25519 master keys, SHA-256
     digests, and Ed25519 signatures thereof in server descriptors and
     extra-info descriptors, and support Ed25519 master keys in votes.
   - Include RSA-1024 signatures of SHA-1 digests of extra-info
     descriptors, which were parsed and discarded before.


# Changes in version 1.0.0 - 2015-12-05

 * Major changes
   - This is the initial release after four years of development.
     Happy 4th birthday!

