/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.zip.InflaterInputStream;

/* Download descriptors from one directory authority or mirror.  First,
 * ask the coordinator thread to create a request, run it, and deliver
 * the response.  Repeat until the coordinator thread says there are no
 * further requests to make. */
public class DirectoryDownloader implements Runnable {

  private String nickname;
  private String ipPort;
  protected DirectoryDownloader(String nickname, String ip, int dirPort) {
    this.nickname = nickname;
    this.ipPort = ip + ":" + String.valueOf(dirPort);
  }

  private DownloadCoordinator downloadCoordinator;
  protected void setDownloadCoordinator(
      DownloadCoordinator downloadCoordinator) {
    this.downloadCoordinator = downloadCoordinator;
  }

  private long requestTimeout;
  protected void setRequestTimeout(long requestTimeout) {
    this.requestTimeout = requestTimeout;
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
        Thread timeoutThread = new Thread(new RequestTimeout(
            this.requestTimeout));
        timeoutThread.start();
        try {
          URL u = new URL(url);
          HttpURLConnection huc =
              (HttpURLConnection) u.openConnection();
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
          }
        } catch (IOException e) {
          /* Stop downloading from this directory if there are any
           * problems, e.g., refused connections. */
          keepRunning = false;
        }
        /* TODO How do we find out if we were interrupted, and by who?
         * Set the request or global timeout flag in the response. */
        timeoutThread.interrupt();
        this.downloadCoordinator.deliverResponse(request);
      } else {
        keepRunning = false;
      }
    } while (keepRunning);
  }

  /* Interrupt a download request if it takes longer than a given time. */
  private static class RequestTimeout implements Runnable {
    private long timeoutMillis;
    private Thread downloaderThread;
    private RequestTimeout(long timeoutMillis) {
      this.downloaderThread = Thread.currentThread();
      this.timeoutMillis = timeoutMillis;
    }
    public void run() {
      long started = System.currentTimeMillis(), sleep;
      while ((sleep = started + this.timeoutMillis
          - System.currentTimeMillis()) > 0L) {
        try {
          Thread.sleep(sleep);
        } catch (InterruptedException e) {
          return;
        }
      }
      this.downloaderThread.interrupt();
    }
  }
}

