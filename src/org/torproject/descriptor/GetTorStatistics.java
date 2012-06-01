package org.torproject.descriptor;

import java.util.SortedMap;

public interface GetTorStatistics {

  /* Return the date of these GetTor statistics in milliseconds since
   * 1970-01-01 00:00:00. */
  public long getDateMillis();

  /* Return the number of downloaded packages. */
  public SortedMap<String, Integer> getDownloadedPackages();
}
