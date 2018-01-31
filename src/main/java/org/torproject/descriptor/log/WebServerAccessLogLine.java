/* Copyright 2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
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

  private String ip;
  private int response;
  private String request;
  private Method method;
  private LocalDate date;
  private String protocol;
  private int size = -1;
  private boolean valid = false;
  private String type;

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
        this.type, this.response, this.size < 0 ? DASH : this.size);
  }

  /** Returns the string of the date using 'yyyymmdd' format. */
  public String getDateString() {
    return this.date.format(DateTimeFormatter.ofPattern(DATE_PATTERN));
  }

  /** Returns a string containing the ip. */
  public String getIp() {
    return this.ip;
  }

  /** Only used internally during sanitization. */
  public void setIp(String ip) {
    this.ip = ip;
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
    this.request = request;
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
        res.protocol = mat.group(9);
        String dateTimeString = mat.group(4) + mat.group(5) + mat.group(6);
        res.date = ZonedDateTime.parse(dateTimeString,
            dateTimeFormatter).withZoneSameInstant(ZoneOffset.UTC)
            .toLocalDate();
        res.ip = mat.group(1);
        res.request = mat.group(8);
        res.type = mat.group(9);
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

}

