/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.SortedMap;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class ParseHelper {

  private static Pattern ipv4Pattern =
      Pattern.compile("^[0-9\\.]{7,15}$");
  public static String parseIpv4Address(String line, String address)
      throws DescriptorParseException {
    boolean isValid = true;
    if (!ipv4Pattern.matcher(address).matches()) {
      isValid = false;
    } else {
      String[] parts = address.split("\\.", -1);
      if (parts.length != 4) {
        isValid = false;
      } else {
        for (int i = 0; i < 4; i++) {
          try {
            int octetValue = Integer.parseInt(parts[i]);
            if (octetValue < 0 || octetValue > 255) {
              isValid = false;
            }
          } catch (NumberFormatException e) {
            isValid = false;
          }
        }
      }
    }
    if (!isValid) {
      throw new DescriptorParseException("'" + address + "' in line '"
          + line + "' is not a valid IPv4 address.");
    }
    return address;
  }

  public static int parsePort(String line, String portString)
      throws DescriptorParseException {
    int port = -1;
    try {
      port = Integer.parseInt(portString);
    } catch (NumberFormatException e) {
      throw new DescriptorParseException("'" + portString + "' in line '"
          + line + "' is not a valid port number.");
    }
    if (port < 0 || port > 65535) {
      throw new DescriptorParseException("'" + portString + "' in line '"
          + line + "' is not a valid port number.");
    }
    return port;
  }

  public static long parseSeconds(String line, String secondsString)
      throws DescriptorParseException {
    try {
      return Long.parseLong(secondsString);
    } catch (NumberFormatException e) {
      throw new DescriptorParseException("'" + secondsString + "' in "
          + "line '" + line + "' is not a valid time in seconds.");
    }
  }

  public static String parseExitPattern(String line, String exitPattern)
      throws DescriptorParseException {
    if (!exitPattern.contains(":")) {
      throw new DescriptorParseException("'" + exitPattern + "' in line '"
          + line + "' must contain address and port.");
    }
    String[] parts = exitPattern.split(":");
    String addressPart = parts[0];
    /* TODO Extend to IPv6. */
    if (addressPart.equals("*")) {
      /* Nothing to check. */
    } else if (addressPart.contains("/")) {
      String[] addressParts = addressPart.split("/");
      String address = addressParts[0];
      String mask = addressParts[1];
      ParseHelper.parseIpv4Address(line, address);
      if (addressParts.length != 2) {
        throw new DescriptorParseException("'" + addressPart + "' in "
            + "line '" + line + "' is not a valid address part.");
      }
      if (mask.contains(".")) {
        ParseHelper.parseIpv4Address(line, mask);
      } else {
        int maskValue = -1;
        try {
          maskValue = Integer.parseInt(mask);
        } catch (NumberFormatException e) {
          /* Handle below. */
        }
        if (maskValue < 0 || maskValue > 32) {
          throw new DescriptorParseException("'" + mask + "' in line '"
              + line + "' is not a valid IPv4 mask.");
        }
      }
    } else {
      ParseHelper.parseIpv4Address(line, addressPart);
    }
    String portPart = parts[1];
    if (portPart.equals("*")) {
      /* Nothing to check. */
    } else if (portPart.contains("-")) {
      String[] portParts = portPart.split("-");
      String fromPort = portParts[0];
      ParseHelper.parsePort(line, fromPort);
      String toPort = portParts[1];
      ParseHelper.parsePort(line, toPort);
    } else {
      ParseHelper.parsePort(line, portPart);
    }
    return exitPattern;
  }

  public static long parseTimestampAtIndex(String line, String[] parts,
      int dateIndex, int timeIndex) throws DescriptorParseException {
    if (dateIndex >= parts.length || timeIndex >= parts.length) {
      throw new DescriptorParseException("Line '" + line + "' does not "
          + "contain a timestamp at the expected position.");
    }
    long result = -1L;
    try {
      SimpleDateFormat dateTimeFormat = new SimpleDateFormat(
          "yyyy-MM-dd HH:mm:ss");
      dateTimeFormat.setLenient(false);
      dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      result = dateTimeFormat.parse(
          parts[dateIndex] + " " + parts[timeIndex]).getTime();
    } catch (ParseException e) {
      /* Leave result at -1L. */
    }
    if (result < 0L || result / 1000L > (long) Integer.MAX_VALUE) {
      throw new DescriptorParseException("Illegal timestamp format in "
          + "line '" + line + "'.");
    }
    return result;
  }

  public static long parseDateAtIndex(String line, String[] parts,
      int dateIndex) throws DescriptorParseException {
    if (dateIndex >= parts.length) {
      throw new DescriptorParseException("Line '" + line + "' does not "
          + "contain a date at the expected position.");
    }
    long result = -1L;
    try {
      SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
      dateFormat.setLenient(false);
      dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      result = dateFormat.parse(parts[dateIndex]).getTime();
    } catch (ParseException e) {
      /* Leave result at -1L. */
    }
    if (result < 0L || result / 1000L > (long) Integer.MAX_VALUE) {
      throw new DescriptorParseException("Illegal date format in line '"
          + line + "'.");
    }
    return result;
  }

  private static Pattern twentyByteHexPattern =
      Pattern.compile("^[0-9a-fA-F]{40}$");
  public static String parseTwentyByteHexString(String line,
      String hexString) throws DescriptorParseException {
    if (!twentyByteHexPattern.matcher(hexString).matches()) {
      throw new DescriptorParseException("Illegal hex string in line '"
          + line + "'.");
    }
    return hexString.toUpperCase();
  }

  public static SortedMap<String, Integer> parseKeyValuePairs(String line,
      String[] parts, int startIndex, String separatorString)
      throws DescriptorParseException {
    SortedMap<String, Integer> result = new TreeMap<String, Integer>();
    for (int i = startIndex; i < parts.length; i++) {
      String pair = parts[i];
      String[] pairParts = pair.split(separatorString);
      if (pairParts.length != 2) {
        throw new DescriptorParseException("Illegal key-value pair in "
            + "line '" + line + "'.");
      }
      String pairName = pairParts[0];
      try {
        int pairValue = Integer.parseInt(pairParts[1]);
        result.put(pairName, pairValue);
      } catch (NumberFormatException e) {
        throw new DescriptorParseException("Illegal value in line '"
            + line + "'.");
      }
    }
    return result;
  }

  private static Pattern nicknamePattern =
      Pattern.compile("^[0-9a-zA-Z]{1,19}$");
  public static String parseNickname(String line, String nickname)
      throws DescriptorParseException {
    if (!nicknamePattern.matcher(nickname).matches()) {
      throw new DescriptorParseException("Illegal nickname in line '"
          + line + "'.");
    }
    return nickname;
  }

  private static Pattern base64Pattern =
      Pattern.compile("^[0-9a-zA-Z+/]{27}$");
  public static String parseTwentyByteBase64String(String line,
      String base64String) throws DescriptorParseException {
    if (!base64Pattern.matcher(base64String).matches()) {
      throw new DescriptorParseException("'" + base64String
          + "' in line '" + line + "' is not a valid base64-encoded "
          + "20-byte value.");
    }
    return Hex.encodeHexString(Base64.decodeBase64(base64String + "=")).
        toUpperCase();
  }

  public static SortedMap<String, Integer>
      parseCommaSeparatedKeyValueList(String line, String[] partsNoOpt,
      int index, int keyLength) throws DescriptorParseException {
    SortedMap<String, Integer> result = new TreeMap<String, Integer>();
    if (partsNoOpt.length < index) {
      throw new DescriptorParseException("Line '" + line + "' does not "
          + "contain a key-value list at index " + index + ".");
    } else if (partsNoOpt.length > index + 1 ) {
      throw new DescriptorParseException("Line '" + line + "' contains "
          + "unrecognized values beyond the expected key-value list at "
          + "index " + index + ".");
    } else if (partsNoOpt.length > index) {
      String[] listElements = partsNoOpt[index].split(",", -1);
      for (String listElement : listElements) {
        String[] keyAndValue = listElement.split("=");
        String key = null;
        int value = -1;
        if (keyAndValue.length == 2 && (keyLength == 0 ||
            keyAndValue[0].length() == keyLength)) {
          try {
            value = Integer.parseInt(keyAndValue[1]);
            key = keyAndValue[0];
          } catch (NumberFormatException e) {
            /* Handle below. */
          }
        }
        if (key == null) {
          throw new DescriptorParseException("Line '" + line + "' "
              + "contains an illegal key or value in list element '"
              + listElement + "'.");
        }
        result.put(key, value);
      }
    }
    return result;
  }

  public static List<Integer> parseCommaSeparatedIntegerValueList(
      String line, String[] partsNoOpt, int index)
      throws DescriptorParseException {
    List<Integer> result = new ArrayList<Integer>();
    if (partsNoOpt.length < index) {
      throw new DescriptorParseException("Line '" + line + "' does not "
          + "contain a comma-separated value list at index " + index
          + ".");
    } else if (partsNoOpt.length > index + 1 ) {
      throw new DescriptorParseException("Line '" + line + "' contains "
          + "unrecognized values beyond the expected comma-separated "
          + "value list at index " + index + ".");
    } else if (partsNoOpt.length > index) {
      String[] listElements = partsNoOpt[index].split(",", -1);
      for (String listElement : listElements) {
        try {
          result.add(Integer.parseInt(listElement));
        } catch (NumberFormatException e) {
          throw new DescriptorParseException("Line '" + line + "' "
              + "contains an illegal value in list element '"
              + listElement + "'.");
        }
      }
    }
    return result;
  }

  public static List<Double> parseCommaSeparatedDoubleValueList(
      String line, String[] partsNoOpt, int index)
      throws DescriptorParseException {
    List<Double> result = new ArrayList<Double>();
    if (partsNoOpt.length < index) {
      throw new DescriptorParseException("Line '" + line + "' does not "
          + "contain a comma-separated value list at index " + index
          + ".");
    } else if (partsNoOpt.length > index + 1 ) {
      throw new DescriptorParseException("Line '" + line + "' contains "
          + "unrecognized values beyond the expected comma-separated "
          + "value list at index " + index + ".");
    } else if (partsNoOpt.length > index) {
      String[] listElements = partsNoOpt[index].split(",", -1);
      for (String listElement : listElements) {
        try {
          result.add(Double.parseDouble(listElement));
        } catch (NumberFormatException e) {
          throw new DescriptorParseException("Line '" + line + "' "
              + "contains an illegal value in list element '"
              + listElement + "'.");
        }
      }
    }
    return result;
  }
}

