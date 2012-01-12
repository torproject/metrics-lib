/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import org.torproject.descriptor.BridgeNetworkStatus;

/* Contains a bridge network status. */
public class BridgeNetworkStatusImpl extends NetworkStatusImpl
    implements BridgeNetworkStatus {

  protected BridgeNetworkStatusImpl(byte[] statusBytes,
      String fileName) throws DescriptorParseException {
    super(statusBytes);
    this.setPublishedMillisFromFileName(fileName);
  }

  private static SimpleDateFormat fileNameFormat = new SimpleDateFormat(
      "yyyyMMdd-HHmmss");
  static {
    fileNameFormat.setLenient(false);
    fileNameFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
  }

  private void setPublishedMillisFromFileName(String fileName)
      throws DescriptorParseException {
    if (fileName.length() == 
        "20000101-000000-4A0CCD2DDC7995083D73F5D667100C8A5831F16D".
        length()) {
      String publishedString = fileName.substring(0,
          "yyyyMMdd-HHmmss".length());
      try {
        this.publishedMillis = fileNameFormat.parse(publishedString).
            getTime();
      } catch (ParseException e) {
      } 
    }
    if (this.publishedMillis == 0L) {
      throw new DescriptorParseException("Unrecognized bridge network "
          + "status file name '" + fileName + "'.");
    }
  }

  protected void parseHeader(byte[] headerBytes)
      throws DescriptorParseException {
    throw new DescriptorParseException("No directory header expected in "
        + "bridge network status.");
  }

  protected void parseDirSource(byte[] dirSourceBytes)
      throws DescriptorParseException {
    throw new DescriptorParseException("No directory source expected in "
        + "bridge network status.");
  }

  protected void parseFooter(byte[] footerBytes)
      throws DescriptorParseException {
    throw new DescriptorParseException("No directory footer expected in "
        + "bridge network status.");
  }

  protected void parseDirectorySignature(byte[] directorySignatureBytes)
      throws DescriptorParseException {
    throw new DescriptorParseException("No directory signature expected "
        + "in bridge network status.");
  }

  private long publishedMillis;
  public long getPublishedMillis() {
    return this.publishedMillis;
  }
}

