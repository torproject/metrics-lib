/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/* Provide an iterator for a queue of objects and block when there are
 * currently no objects in the queue.  Allow the producer to signal that
 * there won't be further objects and unblock any waiting consumers. */
public class BlockingIteratorImpl<T> implements Iterator<T> {

  /* Define an internal class encapsulating queue elements as a workaround
   * for adding an end-of-stream object (containing a null reference) to
   * the queue when the producer runs out of objects. */
  private static class QueueElement<T> {
    private T object;
  }

  /* Blocking queue containing produced elemnts (or the end-of-stream
   * object) waiting for consumers. */
  private BlockingQueue<QueueElement<T>> queue =
      new LinkedBlockingQueue<QueueElement<T>>();

  /* Restrict object construction to the impl package. */
  protected BlockingIteratorImpl() {
  }

  /* Add an object to the queue. */
  protected void add(T object) {
    if (this.outOfDescriptors) {
      throw new IllegalStateException();
    }
    QueueElement<T> element = new QueueElement<T>();
    element.object = object;
    this.queue.add(element);
  }

  /* Signalize that there won't be any further objects to be enqueued. */
  private boolean outOfDescriptors = false;
  protected void setOutOfDescriptors() {
    this.outOfDescriptors = true;
    this.add(null);
  }

  /* Return whether there are more objects.  Block if there are currently
   * no objects, but the producer hasn't signalized that there won't be
   * further objects. */
  public boolean hasNext() {
    QueueElement<T> nextElement = this.queue.peek();
    return ((nextElement != null && nextElement.object != null) ||
        (nextElement == null && !this.outOfDescriptors));
  }

  /* Return the next object in the queue or throw an exception when there
   * are no further objects.  Block if there are currently no objects, but
   * the producer hasn't signalized that there won't be further
   * objects. */
  public T next() {
    QueueElement<T> nextElement = this.queue.peek();
    try {
      nextElement = this.queue.take();
    } catch (InterruptedException e) {
      /* TODO How should we handle this? */
    }
    if (nextElement == null || nextElement.object == null) {
      throw new NoSuchElementException();
    }
    T result = nextElement.object;
    return result;
  }

  /* Don't support explicitly removing objects.  They are removed
   * anyway. */
  public void remove() {
    throw new UnsupportedOperationException();
  }
}

