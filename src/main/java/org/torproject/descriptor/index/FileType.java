/* Copyright 2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.index;

import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorOutputStream;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * A file type enum provides all compression functionality.
 *
 * @since 1.4.0
 */
public enum FileType {
  BZ2(BZip2CompressorInputStream.class, BZip2CompressorOutputStream.class),
  GZ(GzipCompressorInputStream.class, GzipCompressorOutputStream.class),
  JSON(BufferedInputStream.class, BufferedOutputStream.class),
  XZ(XZCompressorInputStream.class, XZCompressorOutputStream.class);

  private final Class<? extends InputStream> inClass;
  private final Class<? extends OutputStream> outClass;

  FileType(Class<? extends InputStream> in, Class<? extends OutputStream> out) {
    this.inClass = in;
    this.outClass = out;
  }

  /** Return the appropriate input stream. */
  public InputStream inputStream(InputStream is) throws Exception {
    return this.inClass.getConstructor(new Class[]{InputStream.class})
        .newInstance(is);
  }

  /** Return the appropriate output stream. */
  public OutputStream outputStream(OutputStream os) throws Exception {
    return this.outClass.getConstructor(new Class[]{OutputStream.class})
        .newInstance(os);
  }
}

