/* Copyright 2012--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

public interface DirectoryKeyCertificate extends Descriptor {

  /* Return the directory key certificate version. */
  public int getDirKeyCertificateVersion();

  /* Return the IP address, or null if the certificate does not contain an
   * address. */
  public String getAddress();

  /* Return the directory port, or -1 if the certificate does not contain
   * one. */
  public int getPort();

  /* Return the directory identity fingerprint. */
  public String getFingerprint();

  /* Return the directory identity key. */
  public String getDirIdentityKey();

  /* Return the directory key certificate publication timestamp. */
  public long getDirKeyPublishedMillis();

  /* Return the directory key certificate expiration timestamp. */
  public long getDirKeyExpiresMillis();

  /* Return the directory signing key digest. */
  public String getDirSigningKey();

  /* Return the signature of the directory identity key made using the
   * directory signing key, or null if the certificate does not contain
   * this signature. */
  public String getDirKeyCrosscert();

  /* Return the certificate signature made using the directory identity
   * key. */
  public String getDirKeyCertification();

  /* Return the calculated certificate digest. */
  public String getCertificateDigest();
}

