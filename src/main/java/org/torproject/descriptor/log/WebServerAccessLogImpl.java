/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.log;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.WebServerAccessLog;
import org.torproject.descriptor.internal.FileType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStreamReader;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Implementation of web server access log descriptors.
 *
 * <p>Defines sanitization and validation for web server access logs.</p>
 *
 * @since 2.2.0
 */
public class WebServerAccessLogImpl extends LogDescriptorImpl
    implements InternalWebServerAccessLog, WebServerAccessLog {

  private static final Logger log
      = LoggerFactory.getLogger(WebServerAccessLogImpl.class);

  /** The log's name should include this string. */
  public static final String MARKER = InternalWebServerAccessLog.MARKER;

  /** The mandatory web server log descriptor file name pattern. */
  public static final Pattern filenamePattern
      = Pattern.compile("(\\S*)" + SEP + "(\\S*)" + SEP + "" + MARKER
      + SEP + "(\\d*)(?:\\.?)([a-zA-Z]*)");

  private final String physicalHost;

  private final String virtualHost;

  private final LocalDate logDate;

  private boolean validate = true;

  /**
   * Creates a WebServerAccessLog from the given bytes and filename.
   *
   * <p>The given bytes are read, whereas the file is not read.</p>
   *
   * <p>The path of the given file has to be compliant to the following
   * naming pattern
   * {@code
   * <virtualHost>-<physicalHost>-access.log-<yyyymmdd>.<compression>},
   * where an unknown compression type (see {@link #getCompressionType})
   * is interpreted as missing compression.  In this case the bytes
   * will be compressed to the default compression type.
   * The immediate parent name is taken to be the physical host collecting the
   * logs.</p>
   */
  protected WebServerAccessLogImpl(byte[] logBytes, File file)
      throws DescriptorParseException {
    this(logBytes, file, FileType.XZ);
  }

  /** For internal use only. */
  public WebServerAccessLogImpl(Collection<String> lines, String filename,
      boolean validate) throws DescriptorParseException {
    this(LogDescriptorImpl.collectionToBytes(lines), new File(filename),
        FileType.XZ, validate);
  }

  private WebServerAccessLogImpl(byte[] logBytes, File file,
      FileType defaultCompression) throws DescriptorParseException {
    this(logBytes, file, defaultCompression, true);
  }

  private WebServerAccessLogImpl(byte[] logBytes, File file,
      FileType defaultCompression, boolean validate)
      throws DescriptorParseException {
    super(logBytes, file, defaultCompression);
    try {
      String fn = file.toPath().getFileName().toString();
      Matcher mat = filenamePattern.matcher(fn);
      if (!mat.find()) {
        throw new DescriptorParseException(
            "WebServerAccessLog file name doesn't comply to standard: " + fn);
      }
      this.virtualHost = mat.group(1);
      this.physicalHost = mat.group(2);
      if (null == this.virtualHost || null == this.physicalHost
          || this.virtualHost.isEmpty() || this.physicalHost.isEmpty()) {
        throw new DescriptorParseException(
            "WebServerAccessLog file name doesn't comply to standard: " + fn);
      }
      String ymd = mat.group(3);
      this.logDate = LocalDate.parse(ymd, DateTimeFormatter.BASIC_ISO_DATE);
      this.setValidator((line)
          -> WebServerAccessLogLine.makeLine(line).isValid());
      if (validate) {
        this.validate();
      }
    } catch (DescriptorParseException dpe) {
      throw dpe; // escalate
    } catch (Exception pe) {
      throw new DescriptorParseException(
          "Cannot parse WebServerAccessLog file: " + file, pe);
    }
  }

  @Override
  public String getPhysicalHost() {
    return this.physicalHost;
  }

  @Override
  public String getVirtualHost() {
    return this.virtualHost;
  }

  @Override
  public LocalDate getLogDate() {
    return this.logDate;
  }

  /** Returns a list of all valid log lines. */
  @Override
  public List<WebServerAccessLog.Line> logLines()
      throws DescriptorParseException {
    try (BufferedReader br
        = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(
        this.getRawDescriptorBytes())))) {
      return br.lines().map(line
          -> (WebServerAccessLog.Line) WebServerAccessLogLine.makeLine(line))
        .filter(line -> line.isValid()).collect(Collectors.toList());
    } catch (Exception ex) {
      throw new DescriptorParseException("Cannot retrieve log lines.", ex);
    }
  }

}

