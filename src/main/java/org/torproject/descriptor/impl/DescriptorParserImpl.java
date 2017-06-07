/* Copyright 2012--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.torproject.descriptor.impl.DescriptorImpl.NL;
import static org.torproject.descriptor.impl.DescriptorImpl.SP;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.DescriptorParser;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class DescriptorParserImpl implements DescriptorParser {

  private boolean failUnrecognizedDescriptorLines;

  @Override
  public void setFailUnrecognizedDescriptorLines(
      boolean failUnrecognizedDescriptorLines) {
    this.failUnrecognizedDescriptorLines =
        failUnrecognizedDescriptorLines;
  }

  @Override
  public List<Descriptor> parseDescriptors(
      byte[] rawDescriptorBytes, String fileName)
      throws DescriptorParseException {
    byte[] first100Chars = new byte[Math.min(100,
        rawDescriptorBytes.length)];
    System.arraycopy(rawDescriptorBytes, 0, first100Chars, 0,
        first100Chars.length);
    String firstLines = new String(first100Chars);
    if (firstLines.startsWith("@type network-status-consensus-3 1.")
        || firstLines.startsWith(
        "@type network-status-microdesc-consensus-3 1.")
        || ((firstLines.startsWith(
        Key.NETWORK_STATUS_VERSION.keyword + SP + "3")
        || firstLines.contains(
        NL + Key.NETWORK_STATUS_VERSION.keyword + SP + "3"))
        && firstLines.contains(
        NL + Key.VOTE_STATUS.keyword + SP + "consensus" + NL))) {
      return parseDescriptors(rawDescriptorBytes, Key.NETWORK_STATUS_VERSION,
          RelayNetworkStatusConsensusImpl.class,
          this.failUnrecognizedDescriptorLines);
    } else if (firstLines.startsWith("@type network-status-vote-3 1.")
        || ((firstLines.startsWith(
        Key.NETWORK_STATUS_VERSION.keyword + SP + "3" + NL)
        || firstLines.contains(
        NL + Key.NETWORK_STATUS_VERSION.keyword + SP + "3" + NL))
        && firstLines.contains(
        NL + Key.VOTE_STATUS.keyword + SP + "vote" + NL))) {
      return parseDescriptors(rawDescriptorBytes, Key.NETWORK_STATUS_VERSION,
          RelayNetworkStatusVoteImpl.class,
          this.failUnrecognizedDescriptorLines);
    } else if (firstLines.startsWith("@type bridge-network-status 1.")
        || firstLines.startsWith(Key.R.keyword + SP)) {
      List<Descriptor> parsedDescriptors = new ArrayList<>();
      parsedDescriptors.add(new BridgeNetworkStatusImpl(
          rawDescriptorBytes, new int[] { 0, rawDescriptorBytes.length },
          fileName, this.failUnrecognizedDescriptorLines));
      return parsedDescriptors;
    } else if (firstLines.startsWith("@type bridge-server-descriptor 1.")) {
      return parseDescriptors(rawDescriptorBytes, Key.ROUTER,
          BridgeServerDescriptorImpl.class,
          this.failUnrecognizedDescriptorLines);
    } else if (firstLines.startsWith("@type server-descriptor 1.")
        || firstLines.startsWith(Key.ROUTER.keyword + SP)
        || firstLines.contains(NL + Key.ROUTER.keyword + SP)) {
      return parseDescriptors(rawDescriptorBytes, Key.ROUTER,
          RelayServerDescriptorImpl.class,
          this.failUnrecognizedDescriptorLines);
    } else if (firstLines.startsWith("@type bridge-extra-info 1.")) {
      return parseDescriptors(rawDescriptorBytes, Key.EXTRA_INFO,
          BridgeExtraInfoDescriptorImpl.class,
          this.failUnrecognizedDescriptorLines);
    } else if (firstLines.startsWith("@type extra-info 1.")
        || firstLines.startsWith(Key.EXTRA_INFO.keyword + SP)
        || firstLines.contains(NL + Key.EXTRA_INFO.keyword + SP)) {
      return parseDescriptors(rawDescriptorBytes, Key.EXTRA_INFO,
          RelayExtraInfoDescriptorImpl.class,
          this.failUnrecognizedDescriptorLines);
    } else if (firstLines.startsWith("@type microdescriptor 1.")
        || firstLines.startsWith(Key.ONION_KEY.keyword + NL)
        || firstLines.contains(NL + Key.ONION_KEY.keyword + NL)) {
      return parseDescriptors(rawDescriptorBytes, Key.ONION_KEY,
          MicrodescriptorImpl.class, this.failUnrecognizedDescriptorLines);
    } else if (firstLines.startsWith("@type bridge-pool-assignment 1.")
        || firstLines.startsWith(Key.BRIDGE_POOL_ASSIGNMENT.keyword + SP)
        || firstLines.contains(NL + Key.BRIDGE_POOL_ASSIGNMENT.keyword + SP)) {
      return parseDescriptors(rawDescriptorBytes, Key.BRIDGE_POOL_ASSIGNMENT,
          BridgePoolAssignmentImpl.class, this.failUnrecognizedDescriptorLines);
    } else if (firstLines.startsWith("@type dir-key-certificate-3 1.")
        || firstLines.startsWith(Key.DIR_KEY_CERTIFICATE_VERSION.keyword + SP)
        || firstLines.contains(
        NL + Key.DIR_KEY_CERTIFICATE_VERSION.keyword + SP)) {
      return parseDescriptors(rawDescriptorBytes,
          Key.DIR_KEY_CERTIFICATE_VERSION, DirectoryKeyCertificateImpl.class,
          this.failUnrecognizedDescriptorLines);
    } else if (firstLines.startsWith("@type tordnsel 1.")
        || firstLines.startsWith("ExitNode" + SP)
        || firstLines.contains(NL + "ExitNode" + SP)) {
      List<Descriptor> parsedDescriptors = new ArrayList<>();
      parsedDescriptors.add(new ExitListImpl(rawDescriptorBytes, fileName,
          this.failUnrecognizedDescriptorLines));
      return parsedDescriptors;
    } else if (firstLines.startsWith("@type network-status-2 1.")
        || firstLines.startsWith(
        Key.NETWORK_STATUS_VERSION.keyword + SP + "2" + NL)
        || firstLines.contains(
        NL + Key.NETWORK_STATUS_VERSION.keyword + SP + "2" + NL)) {
      return parseDescriptors(rawDescriptorBytes, Key.NETWORK_STATUS_VERSION,
          RelayNetworkStatusImpl.class, this.failUnrecognizedDescriptorLines);
    } else if (firstLines.startsWith("@type directory 1.")
        || firstLines.startsWith(Key.SIGNED_DIRECTORY.keyword + NL)
        || firstLines.contains(NL + Key.SIGNED_DIRECTORY.keyword + NL)) {
      return parseDescriptors(rawDescriptorBytes, Key.SIGNED_DIRECTORY,
          RelayDirectoryImpl.class, this.failUnrecognizedDescriptorLines);
    } else if (firstLines.startsWith("@type torperf 1.")) {
      return TorperfResultImpl.parseTorperfResults(
          rawDescriptorBytes, this.failUnrecognizedDescriptorLines);
    } else {
      throw new DescriptorParseException("Could not detect descriptor "
          + "type in descriptor starting with '" + firstLines + "'.");
    }
  }

  private static List<Descriptor> parseDescriptors(byte[] rawDescriptorBytes,
      Key key, Class<? extends DescriptorImpl> descriptorClass,
      boolean failUnrecognizedDescriptorLines) throws DescriptorParseException {
    List<Descriptor> parsedDescriptors = new ArrayList<>();
    Constructor<? extends DescriptorImpl> constructor;
    try {
      constructor = descriptorClass.getDeclaredConstructor(byte[].class,
          int[].class, boolean.class);
    } catch (NoSuchMethodException e) {
      throw new RuntimeException(e);
    }
    int startAnnotations = 0;
    int endAllDescriptors = rawDescriptorBytes.length;
    String ascii = new String(rawDescriptorBytes, StandardCharsets.US_ASCII);
    boolean containsAnnotations = ascii.startsWith("@")
        || ascii.contains(NL + "@");
    while (startAnnotations < endAllDescriptors) {
      int startDescriptor;
      if (startAnnotations == ascii.indexOf(key.keyword + SP,
          startAnnotations) || startAnnotations == ascii.indexOf(
          key.keyword + NL)) {
        startDescriptor = startAnnotations;
      } else {
        startDescriptor = ascii.indexOf(NL + key.keyword + SP,
            startAnnotations - 1);
        if (startDescriptor < 0) {
          startDescriptor = ascii.indexOf(NL + key.keyword + NL,
              startAnnotations - 1);
        }
        if (startDescriptor < 0) {
          break;
        } else {
          startDescriptor += 1;
        }
      }
      int endDescriptor = -1;
      if (containsAnnotations) {
        endDescriptor = ascii.indexOf(NL + "@", startDescriptor);
      }
      if (endDescriptor < 0) {
        endDescriptor = ascii.indexOf(NL + key.keyword + SP, startDescriptor);
      }
      if (endDescriptor < 0) {
        endDescriptor = ascii.indexOf(NL + key.keyword + NL, startDescriptor);
      }
      if (endDescriptor < 0) {
        endDescriptor = endAllDescriptors - 1;
      }
      endDescriptor += 1;
      int[] offsetAndLength = new int[] { startAnnotations,
          endDescriptor - startAnnotations };
      parsedDescriptors.add(parseDescriptor(rawDescriptorBytes,
          offsetAndLength, constructor, failUnrecognizedDescriptorLines));
      startAnnotations = endDescriptor;
    }
    return parsedDescriptors;
  }

  private static Descriptor parseDescriptor(byte[] rawDescriptorBytes,
      int[] offsetAndLength, Constructor<? extends DescriptorImpl> constructor,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    try {
      return constructor.newInstance(rawDescriptorBytes,
          offsetAndLength, failUnrecognizedDescriptorLines);
    } catch (InstantiationException | IllegalAccessException
        | InvocationTargetException e) {
      throw new RuntimeException();
    }
  }

}
