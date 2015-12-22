/* Copyright 2012--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.TorperfResult;

public class TorperfResultImpl extends DescriptorImpl
    implements TorperfResult {

  public static List<Descriptor> parseTorperfResults(
      byte[] rawDescriptorBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    if (rawDescriptorBytes.length == 0) {
      throw new DescriptorParseException("Descriptor is empty.");
    }
    List<Descriptor> parsedDescriptors = new ArrayList<>();
    String descriptorString = new String(rawDescriptorBytes);
    Scanner s = new Scanner(descriptorString).useDelimiter("\n");
    String typeAnnotation = "";
    while (s.hasNext()) {
      String line = s.next();
      if (line.startsWith("@type torperf ")) {
        String[] parts = line.split(" ");
        if (parts.length != 3) {
          throw new DescriptorParseException("Illegal line '" + line
              + "'.");
        }
        String version = parts[2];
        if (!version.startsWith("1.")) {
          throw new DescriptorParseException("Unsupported version in "
              + " line '" + line + "'.");
        }
        typeAnnotation = line + "\n";
      } else {
        parsedDescriptors.add(new TorperfResultImpl(
            (typeAnnotation + line).getBytes(),
            failUnrecognizedDescriptorLines));
        typeAnnotation = "";
      }
    }
    return parsedDescriptors;
  }

  protected TorperfResultImpl(byte[] rawDescriptorBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(rawDescriptorBytes, failUnrecognizedDescriptorLines, false);
    this.parseTorperfResultLine(new String(rawDescriptorBytes));
  }

  private void parseTorperfResultLine(String inputLine)
      throws DescriptorParseException {
    String line = inputLine;
    while (line.startsWith("@") && line.contains("\n")) {
      line = line.split("\n")[1];
    }
    if (line.isEmpty()) {
      throw new DescriptorParseException("Blank lines are not allowed.");
    }
    String[] parts = line.split(" ");
    for (int i = 0; i < parts.length; i++) {
      String keyValue = parts[i];
      String[] keyValueParts = keyValue.split("=");
      if (keyValueParts.length != 2) {
        throw new DescriptorParseException("Illegal key-value pair in "
            + "line '" + line + "'.");
      }
      String key = keyValueParts[0];
      this.markKeyAsParsed(key, line);
      String value = keyValueParts[1];
      if (key.equals("SOURCE")) {
        this.parseSource(value, keyValue, line);
      } else if (key.equals("FILESIZE")) {
        this.parseFileSize(value, keyValue, line);
      } else if (key.equals("START")) {
        this.parseStart(value, keyValue, line);
      } else if (key.equals("SOCKET")) {
        this.parseSocket(value, keyValue, line);
      } else if (key.equals("CONNECT")) {
        this.parseConnect(value, keyValue, line);
      } else if (key.equals("NEGOTIATE")) {
        this.parseNegotiate(value, keyValue, line);
      } else if (key.equals("REQUEST")) {
        this.parseRequest(value, keyValue, line);
      } else if (key.equals("RESPONSE")) {
        this.parseResponse(value, keyValue, line);
      } else if (key.equals("DATAREQUEST")) {
        this.parseDataRequest(value, keyValue, line);
      } else if (key.equals("DATARESPONSE")) {
        this.parseDataResponse(value, keyValue, line);
      } else if (key.equals("DATACOMPLETE")) {
        this.parseDataComplete(value, keyValue, line);
      } else if (key.equals("WRITEBYTES")) {
        this.parseWriteBytes(value, keyValue, line);
      } else if (key.equals("READBYTES")) {
        this.parseReadBytes(value, keyValue, line);
      } else if (key.equals("DIDTIMEOUT")) {
        this.parseDidTimeout(value, keyValue, line);
      } else if (key.startsWith("DATAPERC")) {
        this.parseDataPercentile(value, keyValue, line);
      } else if (key.equals("LAUNCH")) {
        this.parseLaunch(value, keyValue, line);
      } else if (key.equals("USED_AT")) {
        this.parseUsedAt(value, keyValue, line);
      } else if (key.equals("PATH")) {
        this.parsePath(value, keyValue, line);
      } else if (key.equals("BUILDTIMES")) {
        this.parseBuildTimes(value, keyValue, line);
      } else if (key.equals("TIMEOUT")) {
        this.parseTimeout(value, keyValue, line);
      } else if (key.equals("QUANTILE")) {
        this.parseQuantile(value, keyValue, line);
      } else if (key.equals("CIRC_ID")) {
        this.parseCircId(value, keyValue, line);
      } else if (key.equals("USED_BY")) {
        this.parseUsedBy(value, keyValue, line);
      } else if (this.failUnrecognizedDescriptorLines) {
        throw new DescriptorParseException("Unrecognized key '" + key
            + "' in line '" + line + "'.");
      } else {
        if (this.unrecognizedLines == null) {
          this.unrecognizedLines = new ArrayList<>();
        }
        this.unrecognizedLines.add(line);
      }
    }
    this.checkAllRequiredKeysParsed(line);
  }

  private Set<String> parsedKeys = new HashSet<>();
  private Set<String> requiredKeys = new HashSet<>(Arrays.asList(
      ("SOURCE,FILESIZE,START,SOCKET,CONNECT,NEGOTIATE,REQUEST,RESPONSE,"
      + "DATAREQUEST,DATARESPONSE,DATACOMPLETE,WRITEBYTES,READBYTES").
      split(",")));
  private void markKeyAsParsed(String key, String line)
      throws DescriptorParseException {
    if (this.parsedKeys.contains(key)) {
      throw new DescriptorParseException("Key '" + key + "' is contained "
          + "at least twice in line '" + line + "', but must be "
          + "contained at most once.");
    }
    this.parsedKeys.add(key);
    this.requiredKeys.remove(key);
  }
  private void checkAllRequiredKeysParsed(String line)
      throws DescriptorParseException {
    for (String key : this.requiredKeys) {
      throw new DescriptorParseException("Key '" + key + "' is contained "
          + "contained 0 times in line '" + line + "', but must be "
          + "contained exactly once.");
    }
  }

  private void parseSource(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.source = value;
  }

  private void parseFileSize(String value, String keyValue, String line)
      throws DescriptorParseException {
    try {
      this.fileSize = Integer.parseInt(value);
    } catch (NumberFormatException e) {
      throw new DescriptorParseException("Illegal value in '" + keyValue
          + "' in line '" + line + "'.");
    }
  }

  private void parseStart(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.startMillis = this.parseTimestamp(value, keyValue, line);
  }

  private void parseSocket(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.socketMillis = this.parseTimestamp(value, keyValue, line);
  }

  private void parseConnect(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.connectMillis = this.parseTimestamp(value, keyValue, line);
  }

  private void parseNegotiate(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.negotiateMillis = this.parseTimestamp(value, keyValue, line);
  }

  private void parseRequest(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.requestMillis = this.parseTimestamp(value, keyValue, line);
  }

  private void parseResponse(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.responseMillis = this.parseTimestamp(value, keyValue, line);
  }

  private void parseDataRequest(String value, String keyValue,
      String line) throws DescriptorParseException {
    this.dataRequestMillis = this.parseTimestamp(value, keyValue, line);
  }

  private void parseDataResponse(String value, String keyValue,
      String line) throws DescriptorParseException {
    this.dataResponseMillis = this.parseTimestamp(value, keyValue, line);
  }

  private void parseDataComplete(String value, String keyValue,
      String line) throws DescriptorParseException {
    this.dataCompleteMillis = this.parseTimestamp(value, keyValue, line);
  }

  private void parseWriteBytes(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.writeBytes = parseInt(value, keyValue, line);
  }

  private void parseReadBytes(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.readBytes = parseInt(value, keyValue, line);
  }

  private void parseDidTimeout(String value, String keyValue, String line)
      throws DescriptorParseException {
    if (value.equals("1")) {
      this.didTimeout = true;
    } else if (value.equals("0")) {
      this.didTimeout = false;
    } else {
      throw new DescriptorParseException("Illegal value in '" + keyValue
          + "' in line '" + line + "'.");
    }
  }

  private Set<String> unparsedPercentiles = new HashSet<>(
      Arrays.asList("10,20,30,40,50,60,70,80,90".split(",")));
  private void parseDataPercentile(String value, String keyValue,
      String line) throws DescriptorParseException {
    String percentileString = keyValue.substring("DATAPERC".length(),
        keyValue.indexOf("="));
    if (!this.unparsedPercentiles.contains(percentileString)) {
      throw new DescriptorParseException("Illegal value in '" + keyValue
          + "' in line '" + line + "'.");
    }
    this.unparsedPercentiles.remove(percentileString);
    int decileIndex = (Integer.parseInt(percentileString) / 10) - 1;
    long timestamp = this.parseTimestamp(value, keyValue, line);
    this.dataDeciles[decileIndex] = timestamp;
  }

  private void parseLaunch(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.launchMillis = this.parseTimestamp(value, keyValue, line);
  }

  private void parseUsedAt(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.usedAtMillis = this.parseTimestamp(value, keyValue, line);
  }

  private void parsePath(String value, String keyValue, String line)
      throws DescriptorParseException {
    String[] valueParts = value.split(",");
    String[] result = new String[valueParts.length];
    for (int i = 0; i < valueParts.length; i++) {
      if (valueParts[i].length() != 41) {
        throw new DescriptorParseException("Illegal value in '" + keyValue
            + "' in line '" + line + "'.");
      }
      result[i] = ParseHelper.parseTwentyByteHexString(line,
          valueParts[i].substring(1));
    }
    this.path = result;
  }

  private void parseBuildTimes(String value, String keyValue, String line)
      throws DescriptorParseException {
    String[] valueParts = value.split(",");
    Long[] result = new Long[valueParts.length];
    for (int i = 0; i < valueParts.length; i++) {
      result[i] = this.parseTimestamp(valueParts[i], keyValue, line);
    }
    this.buildTimes = result;
  }

  private void parseTimeout(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.timeout = this.parseInt(value, keyValue, line);
  }

  private void parseQuantile(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.quantile = this.parseDouble(value, keyValue, line);
  }

  private void parseCircId(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.circId = this.parseInt(value, keyValue, line);
  }

  private void parseUsedBy(String value, String keyValue, String line)
      throws DescriptorParseException {
    this.usedBy = this.parseInt(value, keyValue, line);
  }

  private long parseTimestamp(String value, String keyValue, String line)
      throws DescriptorParseException {
    long timestamp = -1L;
    if (value.contains(".") && value.split("\\.").length == 2) {
      String zeroPaddedValue = (value + "000");
      String threeDecimalPlaces = zeroPaddedValue.substring(0,
          zeroPaddedValue.indexOf(".") + 4);
      String millisString = threeDecimalPlaces.replaceAll("\\.", "");
      try {
        timestamp = Long.parseLong(millisString);
      } catch (NumberFormatException e) {
        /* Handle below. */
      }
    }
    if (timestamp < 0L) {
      throw new DescriptorParseException("Illegal timestamp '" + value + "' in '"
          + keyValue + "' in line '" + line + "'.");
    }
    return timestamp;
  }

  private int parseInt(String value, String keyValue, String line)
      throws DescriptorParseException {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      throw new DescriptorParseException("Illegal value in '" + keyValue
          + " in line '" + line + "'.");
    }
  }

  private double parseDouble(String value, String keyValue, String line)
      throws DescriptorParseException {
    try {
      return Double.parseDouble(value);
    } catch (NumberFormatException e) {
      throw new DescriptorParseException("Illegal value in '" + keyValue
          + "' in line '" + line + "'.");
    }
  }

  private String source;
  public String getSource() {
    return this.source;
  }

  private int fileSize;
  public int getFileSize() {
    return this.fileSize;
  }

  private long startMillis;
  public long getStartMillis() {
    return this.startMillis;
  }

  private long socketMillis;
  public long getSocketMillis() {
    return this.socketMillis;
  }

  private long connectMillis;
  public long getConnectMillis() {
    return this.connectMillis;
  }

  private long negotiateMillis;
  public long getNegotiateMillis() {
    return this.negotiateMillis;
  }

  private long requestMillis;
  public long getRequestMillis() {
    return this.requestMillis;
  }

  private long responseMillis;
  public long getResponseMillis() {
    return this.responseMillis;
  }

  private long dataRequestMillis;
  public long getDataRequestMillis() {
    return this.dataRequestMillis;
  }

  private long dataResponseMillis;
  public long getDataResponseMillis() {
    return this.dataResponseMillis;
  }

  private long dataCompleteMillis;
  public long getDataCompleteMillis() {
    return this.dataCompleteMillis;
  }

  private int writeBytes;
  public int getWriteBytes() {
    return this.writeBytes;
  }

  private int readBytes;
  public int getReadBytes() {
    return this.readBytes;
  }

  private boolean didTimeout;
  public Boolean didTimeout() {
    return this.didTimeout;
  }

  private Long[] dataDeciles = new Long[9];
  public SortedMap<Integer, Long> getDataPercentiles() {
    if (this.dataDeciles == null) {
      return null;
    }
    SortedMap<Integer, Long> result = new TreeMap<>();
    for (int i = 0; i < dataDeciles.length; i++) {
      if (dataDeciles[i] > 0L) {
        result.put(10 * (i + 1), dataDeciles[i]);
      }
    }
    return result;
  }

  private long launchMillis = -1L;
  public long getLaunchMillis() {
    return this.launchMillis;
  }

  private long usedAtMillis = -1L;
  public long getUsedAtMillis() {
    return this.usedAtMillis;
  }

  private String[] path;
  public List<String> getPath() {
    return this.path == null ? null : Arrays.asList(this.path);
  }

  private Long[] buildTimes;
  public List<Long> getBuildTimes() {
    return this.buildTimes == null ? null :
        Arrays.asList(this.buildTimes);
  }

  private long timeout = -1L;
  public long getTimeout() {
    return this.timeout;
  }

  private double quantile = -1.0;
  public double getQuantile() {
    return this.quantile;
  }

  private int circId = -1;
  public int getCircId() {
    return this.circId;
  }

  private int usedBy = -1;
  public int getUsedBy() {
    return this.usedBy;
  }
}

