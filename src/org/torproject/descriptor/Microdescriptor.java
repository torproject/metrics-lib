/* Copyright 2014--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.List;

/* Contains a relay microdescriptor. */
public interface Microdescriptor extends Descriptor {

  /* Return the descriptor digest that is used to reference this
   * microdescriptor in a network status. */
  public String getMicrodescriptorDigest();

  /* Return the onion key in PEM format. */
  public String getOnionKey();

  /* Return the ntor onion key base64 string with padding omitted, or null
   * if the microdescriptor didn't contain an ntor onion key line. */
  public String getNtorOnionKey();

  /* Return the relay's additional OR addresses and ports contained in
   * or-address lines, or an empty list if the microdescriptor doesn't
   * contain such lines. */
  public List<String> getOrAddresses();

  /* Return nicknames, ($-prefixed) fingerprints, $fingerprint=nickname,
   * or $fingerprint~nickname tuples contained in the family line of this
   * relay, or null if the descriptor does not contain a family line. */
  public List<String> getFamilyEntries();

  /* Return the default policy of the port summary or null if the
   * microdescriptor didn't contain a port summary line. */
  public String getDefaultPolicy();

  /* Return the port list of the port summary or null if the
   * microdescriptor didn't contain a port summary line. */
  public String getPortList();

  /* Return the default policy of the IPv6 port summary or null if the
   * microdescriptor didn't contain an IPv6 port summary line. */
  public String getIpv6DefaultPolicy();

  /* Return the port list of the IPv6 port summary or null if the
   * microdescriptor didn't contain an IPv6 port summary line. */
  public String getIpv6PortList();

  /* Return the optional, base64-encoded RSA-1024 identity that is only
   * included to prevent collisions between microdescriptors, or null if
   * no such identity is included. */
  public String getRsa1024Identity();

  /* Return the optional, base64-encoded Ed25519 identity that is only
   * included to prevent collisions between microdescriptors, or null if
   * no such identity is included. */
  public String getEd25519Identity();
}

