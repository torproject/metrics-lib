/* Copyright 2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WebServerAccessLogLine {

  private static final Logger log = LoggerFactory
      .getLogger(WebServerAccessLogLine.class);

  private static final String DATE_PATTERN = "dd/MMM/yyyy";
  private static final String DASH = "-";

  private static final DateTimeFormatter dateTimeFormatter
      = DateTimeFormatter.ofPattern(DATE_PATTERN + ":HH:mm:ss xxxx");

  private static Pattern logLinePattern = Pattern.compile(
      "^((?:\\d{1,3}\\.){3}\\d{1,3}) (\\S+) (\\S+) "
      + "\\[([\\w/]+)([\\w:]+)(\\s[+\\-]\\d{4})\\] "
      + "\"([A-Z]+) ([^\"]+) ([A-Z]+/\\d\\.\\d)\" "
      + "(\\d{3}) (\\d+|-)(.*)");

  private static Map<String, String> ipMap
      = Collections.synchronizedMap(new HashMap<>());
  private static Map<LocalDate, LocalDate> dateMap
      = Collections.synchronizedMap(new HashMap<>());
  private static Map<String, String> protocolMap
      = Collections.synchronizedMap(new HashMap<>());
  private static Map<String, String> requestMap
      = Collections.synchronizedMap(new HashMap<>());

  private String ip;
  private int response;
  private String request;
  private Method method;
  private LocalDate date;
  private int size = -1;
  private boolean valid = false;
  private String protocol;

  /** Returns a log line string. Possibly empty. */
  public String toLogString() {
    if (!this.valid) {
      return "";
    }
    return toString();
  }

  @Override
  public String toString() {
    return String.format("%s - - [%s:00:00:00 +0000] \"%s %s %s\" %d %s",
        this.ip, this.getDateString(), this.method.name(), this.request,
        this.protocol, this.response, this.size < 0 ? DASH : this.size);
  }

  /** Only used internally during sanitization.
   * Returns the string of the date using 'dd/MMM/yyyy' format. */
  public String getDateString() {
    return this.date.format(DateTimeFormatter.ofPattern(DATE_PATTERN));
  }

  /** Returns a string containing the ip. */
  public String getIp() {
    return this.ip;
  }

  /** Only used internally during sanitization. */
  public void setIp(String ip) {
    this.ip = fromMap(ip, ipMap);
  }

  public Method getMethod() {
    return this.method;
  }

  public String getProtocol() {
    return this.protocol;
  }

  public String getRequest() {
    return this.request;
  }

  public Optional<Integer> getSize() {
    return this.size < 0 ? Optional.empty() : Optional.of(this.size);
  }

  public int getResponse() {
    return this.response;
  }

  /** Only used internally during sanitization. */
  public void setRequest(String request) {
    this.request = fromMap(request, requestMap);
  }

  public LocalDate getDate() {
    return this.date;
  }

  public boolean isValid() {
    return this.valid;
  }

  /** Creates a Line from a string. */
  public static WebServerAccessLogLine makeLine(String line) {
    WebServerAccessLogLine res = new WebServerAccessLogLine();
    try {
      Matcher mat = logLinePattern.matcher(line);
      if (mat.find()) {
        res.response = Integer.valueOf(mat.group(10));
        res.method = Method.valueOf(mat.group(7));
        String dateTimeString = mat.group(4) + mat.group(5) + mat.group(6);
        res.date = fromMap(ZonedDateTime.parse(dateTimeString,
            dateTimeFormatter).withZoneSameInstant(ZoneOffset.UTC)
            .toLocalDate(), dateMap);
        res.ip = fromMap(mat.group(1), ipMap);
        res.request = fromMap(mat.group(8), requestMap);
        res.protocol = fromMap(mat.group(9), protocolMap);
        if (DASH.equals(mat.group(11))) {
          res.size = -1;
        } else {
          res.size = Integer.valueOf(mat.group(11));
        }
        res.valid = true;
      }
    } catch (Throwable th) {
      log.debug("Unmatchable line: '{}'.", line, th);
      return new WebServerAccessLogLine();
    }
    return res;
  }

  private static <T> T fromMap(T val, Map<T, T> map) {
    synchronized (map) {
      T reference = map.get(val);
      if (null == reference) {
        map.put(val, val);
        reference = map.get(val);
      }
      return reference;
    }
  }

}

