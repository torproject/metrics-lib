/* Copyright 2012--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

public interface DirectorySignature {

  /* Return the digest algorithm, which is "sha1" by default. */
  public String getAlgorithm();

  /* Return the directory identity fingerprint. */
  public String getIdentity();

  /* Return the directory signing key digest. */
  public String getSigningKeyDigest();

  /* Return the directory signature made using the signing key. */
  public String getSignature();
}

