/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;

import org.torproject.descriptor.DescriptorParseException;

import org.junit.Test;

public class RelayNetworkStatusImplTest {

  private static final String validHeader = "network-status-version 2\n"
      + "dir-source 194.109.206.212 194.109.206.212 80\n"
      + "fingerprint 7EA6EAD6FD83083C538F44038BBFA077587DD755\n"
      + "contact 1024R/8D56913D Alex de Joode <adejoode@sabotage.org>\n"
      + "published 2012-03-01 00:10:43\n"
      + "dir-options\n"
      + "dir-signing-key\n"
      + "-----BEGIN RSA PUBLIC KEY-----\n"
      + "MIGJAoGBAL7QJ6cmXhMlexV97ehnV5hn5ePOeo0sbDYXhlfw52CheEycoUqSD9Y/\n"
      + "3qEo0Rm7XTEol0dRW34ca1LMIXGM4B4whXxBKCRRYe1RY6nF70zb2EUuaHWEWc+f\n"
      + "c6JWYUWZSPpW1uyjyLPUI/ikyyH7zmtR4MfhSeNdt2zSakojYNaPAgMBAAE=\n"
      + "-----END RSA PUBLIC KEY-----\n";

  private static final String validStatus =
      "@type network-status-2 1.0\n" + validHeader;

  @Test(expected = DescriptorParseException.class)
  public void testParseBrokenHeader() throws DescriptorParseException {
    RelayNetworkStatusImpl rnsi
        = new RelayNetworkStatusImpl(validStatus.getBytes(), true);
    rnsi.parseHeader("network-status-version 2\nxyx\nabc".getBytes());
  }

  @Test()
  public void testValidHeader() throws DescriptorParseException {
    RelayNetworkStatusImpl rnsi =
        new RelayNetworkStatusImpl(validStatus.getBytes(), true);
    rnsi.parseHeader(validHeader.getBytes());
    assertEquals(rnsi.getContactLine(),
        "1024R/8D56913D Alex de Joode <adejoode@sabotage.org>");
  }
}

