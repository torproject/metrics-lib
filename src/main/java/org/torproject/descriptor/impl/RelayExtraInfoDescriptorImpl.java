/* Copyright 2015--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.RelayExtraInfoDescriptor;

public class RelayExtraInfoDescriptorImpl
    extends ExtraInfoDescriptorImpl implements RelayExtraInfoDescriptor {

  protected RelayExtraInfoDescriptorImpl(byte[] descriptorBytes,
      int[] offsetAndLimit, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(descriptorBytes, offsetAndLimit, failUnrecognizedDescriptorLines);
    this.calculateDigestSha1Hex(Key.EXTRA_INFO.keyword + SP,
        NL + Key.ROUTER_SIGNATURE.keyword + NL);
    this.calculateDigestSha256Base64(Key.EXTRA_INFO.keyword + SP,
        NL + "-----END SIGNATURE-----" + NL);
  }
}

