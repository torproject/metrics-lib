# Changes in version 1.6.0 - 2016-??-??

 * Medium changes
   - Add two methods for loading and saving a parse history file in
     the descriptor reader to avoid situations where applications fail
     after all descriptors are read but before they are all processed.
   - Unify the build process by adding git-submodule metrics-base in
     src/build and removing all centralized parts of the build
     process.
   - Avoid deleting extraneous local descriptor files when collecting
     descriptors from CollecTor.
   - Turn the descriptor reader thread into a daemon thread, so that
     the application can decide at any time to stop consuming
     descriptors without having to worry about the reader thread not
     being done.
   - Parse "proto" lines in server descriptors, "pr" lines in status
     entries, and "(recommended|required)-(client|relay)-protocols"
     lines in consensuses and votes.


# Changes in version 1.5.0 - 2016-10-19

 * Major changes
   - Make the DescriptorCollector implementation that uses CollecTor's
     index.json file to determine which descriptor files to fetch the
     new default.  Applications must provide gson-2.2.4.jar or higher
     as dependency.

 * Minor changes
   - Avoid running into an IOException and logging a warning for it.


# Changes in version 1.4.0 - 2016-08-31

 * Major changes
   - Add the Simple Logging Facade for Java (slf4j) for logging
     support rather than printing warnings to stderr.  Applications
     must provide slf4j-api-1.7.7.jar or higher as dependency and can
     optionally provide a compatible logging framework of their choice
     (java.util.logging, logback, log4j).

 * Medium changes
   - Add an alpha version of a DescriptorCollector implementation that
     is not enabled by default and that uses CollecTor's index.json
     file to determine which descriptor files to fetch.  Applications
     can enable this implementation by providing gson-2.2.4.jar or
     higher as dependency and setting property descriptor.collector to
     org.torproject.descriptor.index.DescriptorIndexCollector.

 * Minor changes
   - Include resource files in src/*/resources/ in the release
     tarball.
   - Move executable, source, and javadoc jar to generated/dist/.


# Changes in version 1.3.1 - 2016-08-01

 * Medium changes
   - Adapt to CollecTor's new date format to make DescriptorCollector
     work again.


# Changes in version 1.3.0 - 2016-07-06

 * Medium changes
   - Parse "package" lines in consensuses and votes.
   - Support more than one "directory-signature" line in a vote, which
     may become relevant when authorities start signing votes using
     more than one algorithm.
   - Provide directory signatures in consensuses and votes in a list
     rather than a map to support multiple signatures made using the
     same identity key digest but different algorithms.
   - Be more lenient about digest lengths in directory signatures
     which may be longer or shorter than 20 bytes.
   - Parse "tunnelled-dir-server" lines in server descriptors.

 * Minor changes
   - Stop reporting "-----END .*-----" lines in v2 network statuses as
     unrecognized.


# Changes in version 1.2.0 - 2016-05-31

 * Medium changes
   - Include the hostname in directory source entries of consensuses
     and votes.
   - Also accept \r\n as newline in Torperf results files.
   - Make unrecognized keys of Torperf results available together with
     the corresponding values, rather than just the whole line.
   - In Torperf results, recognize all percentiles of expected bytes
     read for 0 <= x <= 100 rather than just x = { 10, 20, ..., 90 }.
   - Rename properties for overriding default descriptor source
     implementation classes.
   - Actually return the signing key digest in network status votes.
   - Parse crypto parts in network status votes.
   - Document all public parts in org.torproject.descriptor and add
     an Ant target to generate Javadocs.

 * Minor changes
   - Include a Torperf results line with more than one unrecognized
     key only once in the unrecognized lines.
   - Make "consensus-methods" line optional in network statuses votes,
     which would mean that only method 1 is supported.
   - Stop reporting "-----END .*-----" lines in directory key
     certificates as unrecognized.
   - Add code used for benchmarking.


# Changes in version 1.1.0 - 2015-12-28

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
   - Support hidden-service statistics in extra-info descriptors.
   - Support onion-key and ntor-onion-key cross certificates in server
     descriptors.

 * Minor changes
   - Start using Java 7 features like the diamond operator and switch
     on String, and use StringBuilder correctly in many places.


# Changes in version 1.0.0 - 2015-12-05

 * Major changes
   - This is the initial release after four years of development.
     Happy 4th birthday!

