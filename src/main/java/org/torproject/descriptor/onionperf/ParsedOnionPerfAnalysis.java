/* Copyright 2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.onionperf;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;

import java.io.IOException;
import java.util.Map;

/**
 * Parsed OnionPerf analysis document with all relevant fields for
 * {@link OnionPerfAnalysisConverter} to convert contained measurements to
 * {@link org.torproject.descriptor.TorperfResult} instances.
 */
public class ParsedOnionPerfAnalysis {

  /**
   * Object mapper for deserializing OnionPerf analysis documents to instances
   * of this class.
   */
  private static final ObjectMapper objectMapper = new ObjectMapper()
      .setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE)
      .setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.NONE)
      .setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY)
      .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

  /**
   * Deserialize an OnionPerf analysis document from the given uncompressed
   * bytes.
   *
   * @param bytes Uncompressed contents of the OnionPerf analysis to
   *     deserialize.
   * @return Parsed OnionPerf analysis document.
   * @throws IOException Thrown if something goes wrong while deserializing the
   *     given JSON document, but before doing any verification or
   *     postprocessing.
   */
  static ParsedOnionPerfAnalysis fromBytes(byte[] bytes) throws IOException {
    return objectMapper.readValue(bytes, ParsedOnionPerfAnalysis.class);
  }

  /**
   * OnionPerf measurement data by source nickname.
   */
  Map<String, MeasurementData> data;

  /**
   * Descriptor type, which should always be {@code "onionperf"} for OnionPerf
   * analysis documents.
   */
  String type;

  /**
   * Document version, which is either a {@link Double} in version 1.0 or a
   * {@link String} in subsequent versions.
   */
  Object version;

  /**
   * Measurement data obtained from client-side {@code tgen} and {@code tor}
   * controller event logs.
   */
  static class MeasurementData {

    /**
     * Public IP address of the OnionPerf host obtained by connecting to
     * well-known servers and finding the IP address in the result, which may be
     * {@code "unknown"} if OnionPerf was not able to find this information.
     */
    String measurementIp;

    /**
     * Measurement data obtained from client-side {@code tgen} logs.
     */
    TgenData tgen;

    /**
     * Measurement data obtained from client-side {@code tor} controller event
     * logs.
     */
    TorData tor;
  }

  /**
   * Measurement data obtained from client-side {@code tgen} logs.
   */
  static class TgenData {

    /**
     * Measurement data by transfer identifier.
     */
    Map<String, Transfer> transfers;
  }

  /**
   * Measurement data related to a single transfer obtained from client-side
   * {@code tgen} logs.
   */
  static class Transfer {

    /**
     * Elapsed seconds between starting a transfer at {@link #unixTsStart} and
     * reaching a set of pre-defined states.
     */
    ElapsedSeconds elapsedSeconds;

    /**
     * Hostname, IP address, and port that the {@code tgen} client used to
     * connect to the local {@code tor} SOCKS port, formatted as
     * {@code "hostname:ip:port"}, which may be {@code "NULL:0.0.0.0:0"} if
     * {@code tgen} was not able to find this information.
     */
    String endpointLocal;

    /**
     * Hostname, IP address, and port that the {@code tgen} client used to
     * connect to the SOCKS proxy server that {@code tor} runs, formatted as
     * {@code "hostname:ip:port"}, which may be {@code "NULL:0.0.0.0:0"} if
     * {@code tgen} was not able to find this information.
     */
    String endpointProxy;

    /**
     * Hostname, IP address, and port that the {@code tgen} client used to
     * connect to the remote server, formatted as {@code "hostname:ip:port"},
     * which may be {@code "NULL:0.0.0.0:0"} if {@code tgen} was not able to
     * find this information.
     */
    String endpointRemote;

    /**
     * Error code reported in the client {@code tgen} logs, which can be
     * {@code "NONE"} if no error was encountered, {@code "PROXY"} in case of an
     * error in {@code tor}, or something else for {@code tgen}-specific errors.
     */
    String errorCode;

    /**
     * File size in bytes of the requested file in this transfer.
     */
    Integer filesizeBytes;

    /**
     * Client machine hostname, which may be {@code "(NULL)"} if the
     * {@code tgen} client was not able to find this information.
     */
    String hostnameLocal;

    /**
     * Server machine hostname, which may be {@code "(NULL)"} if the
     * {@code tgen} server was not able to find this information.
     */
    String hostnameRemote;

    /**
     * Whether or not an error was encountered in this transfer.
     */
    Boolean isError;

    /**
     * Total number of bytes read in this transfer.
     */
    Integer totalBytesRead;

    /**
     * Total number of bytes written in this transfer.
     */
    Integer totalBytesWrite;

    /**
     * Unix timestamp when this transfer started.
     */
    Double unixTsStart;

    /**
     * Unix timestamp when this transfer ended.
     */
    Double unixTsEnd;
  }

  /**
   * Elapsed seconds between starting a transfer and reaching a set of
   * pre-defined states.
   */
  static class ElapsedSeconds {

    /**
     * Time until the HTTP request was written.
     */
    Double command;

    /**
     * Time until the payload was complete.
     */
    Double lastByte;

    /**
     * Time until the given number of bytes were read.
     */
    Map<String, Double> payloadBytes;

    /**
     * Time until the given fraction of expected bytes were read.
     */
    Map<String, Double> payloadProgress;

    /**
     * Time until SOCKS 5 authentication methods have been negotiated.
     */
    Double proxyChoice;

    /**
     * Time until the SOCKS request was sent.
     */
    Double proxyRequest;

    /**
     * Time until the SOCKS response was received.
     */
    Double proxyResponse;

    /**
     * Time until the first response was received.
     */
    Double response;

    /**
     * Time until the socket was connected.
     */
    Double socketConnect;

    /**
     * Time until the socket was created.
     */
    Double socketCreate;
  }

  /**
   * Measurement data obtained from client-side {@code tor} controller event
   * logs.
   */
  static class TorData {

    /**
     * Circuits by identifier.
     */
    Map<String, Circuit> circuits;

    /**
     * Streams by identifier.
     */
    Map<String, Stream> streams;
  }

  /**
   * Measurement data related to a single circuit obtained from client-side
   * {@code tor} controller event logs.
   */
  static class Circuit {

    /**
     * Circuit build time quantile that the {@code tor} client uses to determine
     * its circuit-build timeout.
     */
    Double buildQuantile;

    /**
     * Circuit build timeout in milliseconds that the {@code tor} client used
     * when building this circuit.
     */
    Integer buildTimeout;

    /**
     * Circuit identifier.
     */
    Integer circuitId;

    /**
     * Path information as two-dimensional array with a mixed-type
     * {@link Object[]} for each hop with {@code "$fingerprint~nickname"} as
     * first element and elapsed seconds between creating and extending the
     * circuit as second element.
     */
    Object[][] path;

    /**
     * Unix timestamp at the start of this circuit's lifetime.
     */
    Double unixTsStart;
  }

  /**
   * Measurement data related to a single stream obtained from client-side
   * {@code tor} controller event logs.
   */
  static class Stream {

    /**
     * Circuit identifier of the circuit that this stream was attached to.
     */
    String circuitId;

    /**
     * Local reason why this stream failed.
     */
    String failureReasonLocal;

    /**
     * Remote reason why this stream failed.
     */
    String failureReasonRemote;

    /**
     * Source address and port that requested the connection.
     */
    String source;

    /**
     * Stream identifier.
     */
    Integer streamId;

    /**
     * Unix timestamp at the end of this stream's lifetime.
     */
    Double unixTsEnd;
  }
}

