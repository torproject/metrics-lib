/* Copyright 2012--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.torproject.descriptor.impl.DescriptorImpl.NL;
import static org.torproject.descriptor.impl.DescriptorImpl.SP;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.DescriptorParser;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class DescriptorParserImpl implements DescriptorParser {

  @Override
  public Iterable<Descriptor> parseDescriptors(byte[] rawDescriptorBytes,
      File descriptorFile, String fileName) {
    try {
      return this.detectTypeAndParseDescriptors(rawDescriptorBytes,
          descriptorFile, fileName);
    } catch (DescriptorParseException e) {
      /* Looks like we attempted to parse the whole raw descriptor bytes at once
       * below and ran into a parse issue. */
      List<Descriptor> parsedDescriptors = new ArrayList<>();
      parsedDescriptors.add(new UnparseableDescriptorImpl(rawDescriptorBytes,
          new int[] { 0, rawDescriptorBytes.length }, descriptorFile, e));
      return parsedDescriptors;
    }
  }

  private List<Descriptor> detectTypeAndParseDescriptors(
      byte[] rawDescriptorBytes, File descriptorFile, String fileName)
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
      return this.parseDescriptors(rawDescriptorBytes, descriptorFile,
          Key.NETWORK_STATUS_VERSION, RelayNetworkStatusConsensusImpl.class);
    } else if (firstLines.startsWith("@type network-status-vote-3 1.")
        || ((firstLines.startsWith(
        Key.NETWORK_STATUS_VERSION.keyword + SP + "3" + NL)
        || firstLines.contains(
        NL + Key.NETWORK_STATUS_VERSION.keyword + SP + "3" + NL))
        && firstLines.contains(
        NL + Key.VOTE_STATUS.keyword + SP + "vote" + NL))) {
      return this.parseDescriptors(rawDescriptorBytes, descriptorFile,
          Key.NETWORK_STATUS_VERSION, RelayNetworkStatusVoteImpl.class);
    } else if (firstLines.startsWith("@type bridge-network-status 1.")
        || firstLines.startsWith(Key.R.keyword + SP)) {
      List<Descriptor> parsedDescriptors = new ArrayList<>();
      parsedDescriptors.add(new BridgeNetworkStatusImpl(
          rawDescriptorBytes, new int[] { 0, rawDescriptorBytes.length },
          descriptorFile, fileName));
      return parsedDescriptors;
    } else if (firstLines.startsWith("@type bridge-server-descriptor 1.")) {
      return this.parseDescriptors(rawDescriptorBytes, descriptorFile,
          Key.ROUTER, BridgeServerDescriptorImpl.class);
    } else if (firstLines.startsWith("@type server-descriptor 1.")
        || firstLines.startsWith(Key.ROUTER.keyword + SP)
        || firstLines.contains(NL + Key.ROUTER.keyword + SP)) {
      return this.parseDescriptors(rawDescriptorBytes, descriptorFile,
          Key.ROUTER, RelayServerDescriptorImpl.class);
    } else if (firstLines.startsWith("@type bridge-extra-info 1.")) {
      return this.parseDescriptors(rawDescriptorBytes, descriptorFile,
          Key.EXTRA_INFO, BridgeExtraInfoDescriptorImpl.class);
    } else if (firstLines.startsWith("@type extra-info 1.")
        || firstLines.startsWith(Key.EXTRA_INFO.keyword + SP)
        || firstLines.contains(NL + Key.EXTRA_INFO.keyword + SP)) {
      return this.parseDescriptors(rawDescriptorBytes, descriptorFile,
          Key.EXTRA_INFO, RelayExtraInfoDescriptorImpl.class);
    } else if (firstLines.startsWith("@type microdescriptor 1.")
        || firstLines.startsWith(Key.ONION_KEY.keyword + NL)
        || firstLines.contains(NL + Key.ONION_KEY.keyword + NL)) {
      return this.parseDescriptors(rawDescriptorBytes, descriptorFile,
          Key.ONION_KEY, MicrodescriptorImpl.class);
    } else if (firstLines.startsWith("@type bridge-pool-assignment 1.")
        || firstLines.startsWith(Key.BRIDGE_POOL_ASSIGNMENT.keyword + SP)
        || firstLines.contains(NL + Key.BRIDGE_POOL_ASSIGNMENT.keyword + SP)) {
      return this.parseDescriptors(rawDescriptorBytes, descriptorFile,
          Key.BRIDGE_POOL_ASSIGNMENT, BridgePoolAssignmentImpl.class);
    } else if (firstLines.startsWith("@type dir-key-certificate-3 1.")
        || firstLines.startsWith(Key.DIR_KEY_CERTIFICATE_VERSION.keyword + SP)
        || firstLines.contains(
        NL + Key.DIR_KEY_CERTIFICATE_VERSION.keyword + SP)) {
      return this.parseDescriptors(rawDescriptorBytes, descriptorFile,
          Key.DIR_KEY_CERTIFICATE_VERSION, DirectoryKeyCertificateImpl.class);
    } else if (firstLines.startsWith("@type tordnsel 1.")
        || firstLines.startsWith("ExitNode" + SP)
        || firstLines.contains(NL + "ExitNode" + SP)) {
      List<Descriptor> parsedDescriptors = new ArrayList<>();
      parsedDescriptors.add(new ExitListImpl(rawDescriptorBytes, descriptorFile,
          fileName));
      return parsedDescriptors;
    } else if (firstLines.startsWith("@type network-status-2 1.")
        || firstLines.startsWith(
        Key.NETWORK_STATUS_VERSION.keyword + SP + "2" + NL)
        || firstLines.contains(
        NL + Key.NETWORK_STATUS_VERSION.keyword + SP + "2" + NL)) {
      return this.parseDescriptors(rawDescriptorBytes, descriptorFile,
          Key.NETWORK_STATUS_VERSION, RelayNetworkStatusImpl.class);
    } else if (firstLines.startsWith("@type directory 1.")
        || firstLines.startsWith(Key.SIGNED_DIRECTORY.keyword + NL)
        || firstLines.contains(NL + Key.SIGNED_DIRECTORY.keyword + NL)) {
      return this.parseDescriptors(rawDescriptorBytes, descriptorFile,
          Key.SIGNED_DIRECTORY, RelayDirectoryImpl.class);
    } else if (firstLines.startsWith("@type torperf 1.")) {
      return TorperfResultImpl.parseTorperfResults(rawDescriptorBytes,
          descriptorFile);
    } else {
      throw new DescriptorParseException("Could not detect descriptor "
          + "type in descriptor starting with '" + firstLines + "'.");
    }
  }

  private List<Descriptor> parseDescriptors(byte[] rawDescriptorBytes,
      File descriptorFile, Key key,
      Class<? extends DescriptorImpl> descriptorClass)
      throws DescriptorParseException {
    List<Descriptor> parsedDescriptors = new ArrayList<>();
    Constructor<? extends DescriptorImpl> constructor;
    try {
      constructor = descriptorClass.getDeclaredConstructor(byte[].class,
          int[].class, File.class);
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
      try {
        parsedDescriptors.add(this.parseDescriptor(rawDescriptorBytes,
            offsetAndLength, descriptorFile, constructor));
      } catch (DescriptorParseException e) {
        parsedDescriptors.add(new UnparseableDescriptorImpl(
            rawDescriptorBytes, offsetAndLength, descriptorFile, e));
      }
      startAnnotations = endDescriptor;
    }
    return parsedDescriptors;
  }

  Descriptor parseDescriptor(byte[] rawDescriptorBytes,
      int[] offsetAndLength, File descriptorFile,
      Constructor<? extends DescriptorImpl> constructor)
      throws DescriptorParseException {
    try {
      return constructor.newInstance(rawDescriptorBytes, offsetAndLength,
          descriptorFile);
    } catch (InvocationTargetException e) {
      if (null != e.getCause()
          && e.getCause() instanceof DescriptorParseException) {
        throw (DescriptorParseException) e.getCause();
      } else {
        throw new RuntimeException(e);
      }
    } catch (InstantiationException | IllegalAccessException e) {
      throw new RuntimeException(e);
    }
  }
}
