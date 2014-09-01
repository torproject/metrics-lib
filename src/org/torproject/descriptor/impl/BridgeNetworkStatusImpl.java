/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.TimeZone;

import org.torproject.descriptor.BridgeNetworkStatus;

/* Contains a bridge network status. */
public class BridgeNetworkStatusImpl extends NetworkStatusImpl
    implements BridgeNetworkStatus {

  protected BridgeNetworkStatusImpl(byte[] statusBytes,
      String fileName, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(statusBytes, failUnrecognizedDescriptorLines, false, false);
    this.setPublishedMillisFromFileName(fileName);
  }

  private void setPublishedMillisFromFileName(String fileName)
      throws DescriptorParseException {
    if (this.publishedMillis != 0L) {
      /* We already learned the publication timestamp from parsing the
       * "published" line. */
      return;
    }
    if (fileName.length() ==
        "20000101-000000-4A0CCD2DDC7995083D73F5D667100C8A5831F16D".
        length()) {
      String publishedString = fileName.substring(0,
          "yyyyMMdd-HHmmss".length());
      try {
        SimpleDateFormat fileNameFormat = new SimpleDateFormat(
            "yyyyMMdd-HHmmss");
        fileNameFormat.setLenient(false);
        fileNameFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
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
    Scanner s = new Scanner(new String(headerBytes)).useDelimiter("\n");
    while (s.hasNext()) {
      String line = s.next();
      String[] parts = line.split("[ \t]+");
      String keyword = parts[0];
      if (keyword.equals("published")) {
        this.parsePublishedLine(line, parts);
      } else if (this.failUnrecognizedDescriptorLines) {
        throw new DescriptorParseException("Unrecognized line '" + line
            + "' in bridge network status.");
      } else {
        if (this.unrecognizedLines == null) {
          this.unrecognizedLines = new ArrayList<String>();
        }
        this.unrecognizedLines.add(line);
      }
    }
  }

  private void parsePublishedLine(String line, String[] parts)
      throws DescriptorParseException {
    this.publishedMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        1, 2);
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

