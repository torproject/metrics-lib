/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

/* Store meta-data about how a descriptor was downloaded or read from
 * disk. */
public interface Descriptor {

  /* Return the raw descriptor bytes. */
  public byte[] getRawDescriptorBytes();
}

