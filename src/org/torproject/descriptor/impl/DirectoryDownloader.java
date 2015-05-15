/* Copyright 2011--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.zip.InflaterInputStream;

import org.torproject.descriptor.DescriptorParser;
import org.torproject.descriptor.DescriptorSourceFactory;

/* Download descriptors from one directory authority or mirror.  First,
 * ask the coordinator thread to create a request, run it, and deliver
 * the response.  Repeat until the coordinator thread says there are no
 * further requests to make. */
public class DirectoryDownloader implements Runnable {

  private String nickname;
  private String ipPort;
  private DescriptorParser descriptorParser;
  protected DirectoryDownloader(String nickname, String ip, int dirPort) {
    this.nickname = nickname;
    this.ipPort = ip + ":" + String.valueOf(dirPort);
    this.descriptorParser =
        DescriptorSourceFactory.createDescriptorParser();
  }

  private DownloadCoordinator downloadCoordinator;
  protected void setDownloadCoordinator(
      DownloadCoordinator downloadCoordinator) {
    this.downloadCoordinator = downloadCoordinator;
  }

  private long connectTimeout;
  protected void setConnectTimeout(long connectTimeout) {
    this.connectTimeout = connectTimeout;
  }

  private long readTimeout;
  protected void setReadTimeout(long readTimeout) {
    this.readTimeout = readTimeout;
  }

  protected void setFailUnrecognizedDescriptorLines(
      boolean failUnrecognizedDescriptorLines) {
    this.descriptorParser.setFailUnrecognizedDescriptorLines(
        failUnrecognizedDescriptorLines);
  }

  public void run() {
    boolean keepRunning = true;
    do {
      DescriptorRequestImpl request =
          this.downloadCoordinator.createRequest(this.nickname);
      if (request != null) {
        String url = "http://" + this.ipPort
            + request.getRequestedResource();
        request.setRequestStart(System.currentTimeMillis());
        try {
          URL u = new URL(url);
          HttpURLConnection huc =
              (HttpURLConnection) u.openConnection();
          huc.setConnectTimeout((int) this.connectTimeout);
          huc.setReadTimeout((int) this.readTimeout);
          huc.setRequestMethod("GET");
          huc.connect();
          int responseCode = huc.getResponseCode();
          request.setResponseCode(responseCode);
          if (responseCode == 200) {
            BufferedInputStream in = new BufferedInputStream(
                new InflaterInputStream(huc.getInputStream()));
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int len;
            byte[] data = new byte[1024];
            while ((len = in.read(data, 0, 1024)) >= 0) {
              baos.write(data, 0, len);
            }
            in.close();
            byte[] responseBytes = baos.toByteArray();
            request.setResponseBytes(responseBytes);
            request.setRequestEnd(System.currentTimeMillis());
            request.setDescriptors(this.descriptorParser.parseDescriptors(
                responseBytes, null));
          }
        } catch (Exception e) {
          request.setException(e);
          /* Stop downloading from this directory if there are any
           * problems, e.g., refused connections. */
          keepRunning = false;
        }
        this.downloadCoordinator.deliverResponse(request);
      } else {
        keepRunning = false;
      }
    } while (keepRunning);
  }
}

