/* Copyright 2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;

import org.torproject.descriptor.DescriptorParseException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.lang.reflect.Constructor;

public class DescriptorParserImplTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  private TestDescriptor makeTestDesc(byte[] bytes) throws Exception {
    return new TestDescriptor(bytes, new int[]{0, bytes.length}, false);
  }

  private static final String MICRO =
      "@type microdescriptor 1.0\n"
      + "onion-key\n"
      + "-----BEGIN RSA PUBLIC KEY-----\n"
      + "MIGJAoGBALzJLYYlkTv6tPet3vusug9judCTrN6MzthV1xVGMSuuWtGHhOJDaIPG\n"
      + "hKdp99CAIU3sLXYO6zDQRF8PL/Z1GK3c+QHuotzfHotR7fMGtUQWNZRs9glVrVdj\n"
      + "6KGAHFHo+9qs6NPg7Ux8Minw3wuaHCqoFbQVXo8F+S3wJE6YQ37HAgMBAAE=\n"
      + "-----END RSA PUBLIC KEY-----\n"
      + "ntor-onion-key RYjTCjtZRvOyfatfubhOjcEib/yDMsyJcjPT82mf6VA=\n"
      + "id ed25519 ihsbrlWToq8b01rvfszqqTMUl2ulyPV3TniKuTENCzY\n";

  @Test
  public void testAnnotation() throws Exception {
    TestDescriptor des = makeTestDesc(MICRO.getBytes());
    DescriptorParserImpl dpi = new DescriptorParserImpl();
    assertEquals(1,
        dpi.parseDescriptors(des.getRawDescriptorBytes(), "dummy.file").size());
  }

  @Test
  public void testParseDescriptor() throws DescriptorParseException {
    Constructor<? extends DescriptorImpl> constructor;
    try {
      constructor = TestServerDescriptor.class
          .getDeclaredConstructor(byte[].class, int[].class, File.class,
          boolean.class);
    } catch (NoSuchMethodException e) {
      throw new RuntimeException(e);
    }
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'176x.158.53.63' in line 'router UbuntuCore169 "
        + "176x.158.53.63 44583 0 0' is not a valid IPv4 address.");
    DescriptorParserImpl dpi = new DescriptorParserImpl();
    dpi.parseDescriptor(DEFECT.getBytes(),
        new int[]{0, DEFECT.getBytes().length}, null, constructor);
  }

  private static final String DEFECT =
      "@type server-descriptor 1.0\n"
      + "router UbuntuCore169 176x.158.53.63 44583 0 0\n"
      + "identity-ed25519\n"
      + "-----BEGIN ED25519 CERT-----\n"
      + "AQQABleiAZ2Ce5QY1oSL0F79WeaPhL/zWomAVJG1vwTioPBkpeG7AQAgBABF3iK6\n"
      + "clXuNv2ZbfNSbmrJkKRLKsC41BZAVs1BSWQndRMNDsZJ/s6GmOd5IiU6axR5z2Nn\n"
      + "XTUR0TMGOc5KNJHqKi9Ht+iSIH02OeV1Gm/PNfos7KBKSJJROme1YQQsvwQ=\n"
      + "-----END ED25519 CERT-----\n"
      + "master-key-ed25x519 Rd4iunJV7jb9mW3zUm5qyZCkSyrAuNQWQFbNQUlkJ3U\n"
      + "platform Tor 0.3.0.6 on Linux\n"
      + "proto Cons=1-2 Desc=1-2 DirCache=1 HSDir=1-2 HSIntro=3-4 HSRend=1-2 Li"
      + "nk=1-4 LinkAuth=1,3 Microdesc=1-2 Relay=1-2\n"
      + "published 2017-05-02 17:25:22\n"
      + "fingerprint 256F 183F 252D BBF0 80F2 E70E 5CB0 F523 A632 3D0F\n"
      + "uptime 12\n"
      + "bandwidth 4194304 6291456 0\n"
      + "extra-info-digest 357F399E5A0FE2EEDEB7B3AD3D9328440EC17582 "
      + "OgEu6BAQLUeTFjGofg0WTT9CYQsUGH9tiDENt/tiAD0\n"
      + "onion-key\n"
      + "-----BEGIN RSA PUBLIC KEY-----\n"
      + "MIGJAoGBAMYpYIFcAGOcfZBWt+nUPDu1ovbG8uamDBN4A/XTla74p6A3Ozl8/06D\n"
      + "1E/CcX6N2UahjDs+iM9EmND0k1CFgnkkkU7qBhm4aeOwfzSjDGXA52ab9vS0yEpa\n"
      + "aFHORGn88LRqcSvm9zRtChde5Ez0QJpBOuhyh19qIsSwT4EVa6CXAgMBAAE=\n"
      + "-----END RSA PUBLIC KEY-----\n"
      + "signing-key\n"
      + "-----BEGIN RSA PUBLIC KEY-----\n"
      + "MIGJAoGBAL6touSlbyMx2frcjIrLXcUUhN9rydnQhZrREZEdpALondnaEZzu3LE8\n"
      + "AeQI+VUTpZBlYbWR3Wh+wMDrdPzB3B07ATjAV3N07x6CtKk8YHE5RgShLlEr1k9c\n"
      + "DhN1VZi3rEA63pVfGTC1n7jXpAkMgYMW4KSHk40kgueu+3JxNSe1AgMBAAE=\n"
      + "-----END RSA PUBLIC KEY-----\n"
      + "onion-key-crosscert\n"
      + "-----BEGIN CROSSCERT-----\n"
      + "ITr+XCRVFqFE5o/5utRst/j8cZjEj43Ucd6n4Xoo566rVS9VPvUszduvPAZJECVS\n"
      + "QHPmshTsvXFH5+LEzCk0nN3cR5+iZX5zT15+1EoplE97doHQqtSTcA1CJSSFvoRj\n"
      + "1iobnqDn1lHLFyTMBJ4VV38a1NeovFmy4YkodTrtztk=\n"
      + "-----END CROSSCERT-----\n"
      + "ntor-onion-key-crosscert 1\n"
      + "-----BEGIN ED25519 CERT-----\n"
      + "AQoABlV6AUXeIrpyVe42/Zlt81JuasmQpEsqwLjUFkBWzUFJZCd1ALsQt0Q8mBNP\n"
      + "FcAXX6E+2oX2nGto910Sb1CBMPenMopKXaqArOPeqEQQx4+4x/waBLw7niBtEVjb\n"
      + "+WZ5cSha6Aw=\n"
      + "-----END ED25519 CERT-----\n"
      + "hidden-service-dir\n"
      + "ntor-onion-key fhiVUl9Ff0OlXd6zyqnfEA8u86KmewZISILHeU33Diw=\n"
      + "reject *:*\n"
      + "tunnelled-dir-server\n"
      + "router-sig-ed25519 pyHeZ3dimbx4cBOAjlhLbnav2F9FLrmy+CqO+QIv01VI4"
      + "qK5xihG6s75HLj3s6dpa52xGBE6HNRdx2rCk2r3Bg\n"
      + "router-signature\n"
      + "-----BEGIN SIGNATURE-----\n"
      + "gJGxrxrbBVnO5x34450bKkBBBGZGJrgfYBLL6tfN6BhEYtENy9cWqt556boXsEuW\n"
      + "cN8z+OdNYr+LGJqUJgGWTSb1am26lU9lyHHHzVIhp9I9K4CXYq93POHCSore0M0c\n"
      + "PgAHPTkUN6WJvxachkEXwftzYaOLvJOqP+GFj+QvsVg=\n"
      + "-----END SIGNATURE-----";
}

