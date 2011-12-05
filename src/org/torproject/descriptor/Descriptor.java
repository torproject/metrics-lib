/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

/* Store meta-data about how a descriptor was downloaded or read from
 * disk. */
public interface Descriptor {

  /* Return the raw descriptor bytes. */
  public byte[] getRawDescriptorBytes();

  /* Return the request as part of which this descriptor was
   * downloaded, or null if this descriptor was not downloaded. */
  public DescriptorRequest getDescriptorRequest();

  /* Return the descriptor file where this descriptor was contained, or
   * null if this descriptor was not read from disk. */
  public DescriptorFile getDescriptorFile();
}

