/**
 * Copyright (c) 2015 Parrot S.A.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of 'Parrot S.A' nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL 'Parrot S.A' BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @file mux_queue.c
 *
 */

#include "mux_priv.h"

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

/** Queue structure */
struct mux_queue {
	pthread_mutex_t     mutex;
	pthread_cond_t      cond;
	uint32_t            head;
	uint32_t            tail;
	uint32_t            used;
	uint32_t            depth;
	int                 growable;
	struct pomp_buffer  **buffers;
	int                 haswaiter;
	int                 stopped;
};

/**
 * Allocate a new queue.
 * @param depth : depth of the queue. 0 for a growable queue.
 * @return new queue or NULL in case of error.
 */
struct mux_queue *mux_queue_new(uint32_t depth)
{
	struct mux_queue *queue = NULL;

	/* Allocate queue structure */
	queue = calloc(1, sizeof(*queue));
	if (queue == NULL)
		return NULL;

	/* Initialize queue depth and growable flag */
	queue->growable = (depth == 0);
	if (depth == 0)
		depth = 16;

	/* Initial buffer list */
	queue->buffers = calloc(depth, sizeof(struct pomp_buffer *));
	if (queue->buffers == NULL) {
		free(queue);
		return NULL;
	}
	queue->depth = depth;
	queue->head = queue->tail = queue->used = 0;

	/* Synchronization */
	pthread_mutex_init(&queue->mutex, NULL);
	pthread_cond_init(&queue->cond, NULL);
	return queue;
}

/**
 * Stop the queue. This will unblock waiter in mux_queue_get_buf by returning
 * -EPIPE to them.
 * @param queue : queue.
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_queue_stop(struct mux_queue *queue)
{
	if (queue == NULL)
		return -EINVAL;

	pthread_mutex_lock(&queue->mutex);
	queue->stopped = 1;
	pthread_cond_signal(&queue->cond);
	pthread_mutex_unlock(&queue->mutex);

	return 0;
}

/**
 * Destroy the queue.
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_queue_destroy(struct mux_queue *queue)
{
	uint32_t i = 0;

	if (queue == NULL)
		return -EINVAL;

	/* Make sure there is no waiter */
	pthread_mutex_lock(&queue->mutex);
	if (queue->haswaiter) {
		pthread_mutex_unlock(&queue->mutex);
		return -EBUSY;
	}
	pthread_mutex_unlock(&queue->mutex);

	/* Free pending buffers */
	for (i = 0; i < queue->depth; i++) {
		if (queue->buffers[i] != NULL)
			pomp_buffer_unref(queue->buffers[i]);
	}

	/* Free resources */
	pthread_cond_destroy(&queue->cond);
	pthread_mutex_destroy(&queue->mutex);
	free(queue->buffers);
	free(queue);
	return 0;
}

/**
 * Put a buffer in the queue.
 * @param queue : queue
 * @param buf : buf. A ne ref is taken.
 * @return 0 in case of success, negative errno value in case of error.
 */
int mux_queue_put_buf(struct mux_queue *queue, struct pomp_buffer *buf)
{
	int res = 0;
	uint32_t newdepth = 0;
	struct pomp_buffer **newbuffers = NULL;
	uint32_t cnt1 = 0, cnt2 = 0;
	if (queue == NULL)
		return -EINVAL;

	pthread_mutex_lock(&queue->mutex);

	/* Grow entries if needed (before it becomes full)
	 * As we are using a circular queue, it is easier to alloc a new array
	 * and copy existing entries at start of it */
	if (queue->used + 1 >= queue->depth) {
		if (!queue->growable) {
			res = -ENOMEM;
			goto out;
		}
		newdepth = queue->depth + 16;
		newbuffers = calloc(newdepth, sizeof(struct pomp_buffer *));
		if (newbuffers == NULL) {
			res = -ENOMEM;
			goto out;
		}

		/* Copy current entries at start of new array*/
		if (queue->head < queue->tail) {
			memcpy(&newbuffers[0], &queue->buffers[queue->head],
					queue->used *
					sizeof(struct pomp_buffer *));
		} else if (queue->head > queue->tail) {
			cnt1 = queue->depth - queue->head;
			cnt2 = queue->tail;
			memcpy(&newbuffers[0],
					&queue->buffers[queue->head],
					cnt1 * sizeof(struct pomp_buffer *));
			memcpy(&newbuffers[cnt1],
					&queue->buffers[0],
					cnt2 * sizeof(struct pomp_buffer *));
		}

		/* Update queue */
		free(queue->buffers);
		queue->head = 0;
		queue->tail = queue->used;
		queue->buffers = newbuffers;
		queue->depth = newdepth;
	}

	/* Add in queue */
	queue->buffers[queue->tail] = buf;
	pomp_buffer_ref(buf);
	queue->tail++;
	if (queue->tail >= queue->depth)
		queue->tail = 0;
	queue->used++;

	/* Wakeup waiter */
	if (queue->haswaiter)
		pthread_cond_signal(&queue->cond);

out:
	pthread_mutex_unlock(&queue->mutex);
	return res;
}


static int mux_queue_get_buf_internal(struct mux_queue *queue,
				      struct pomp_buffer **buf,
				      struct timespec *timeout)
{
	int res = 0;
	struct timespec abs_timeout;
	if (queue == NULL || buf == NULL)
		return -EINVAL;

	pthread_mutex_lock(&queue->mutex);

	/* Only one thread can wait for buffer */
	if (queue->haswaiter) {
		res = -EBUSY;
		goto out;
	}
	queue->haswaiter = 1;

	if (timeout) {
#ifdef __MACH__
		clock_serv_t cclock;
		mach_timespec_t mts;
		host_get_clock_service(mach_host_self(),
				       CALENDAR_CLOCK,
				       &cclock);
		clock_get_time(cclock, &mts);
		mach_port_deallocate(mach_task_self(), cclock);
		abs_timeout.tv_sec = mts.tv_sec;
		abs_timeout.tv_nsec = mts.tv_nsec;
#else
		clock_gettime(CLOCK_REALTIME, &abs_timeout);
#endif
		abs_timeout.tv_sec += timeout->tv_sec;
		abs_timeout.tv_nsec += timeout->tv_nsec;
		while (abs_timeout.tv_nsec > 1000000000) {
			/* over one billion nsec, add 1 sec */
			abs_timeout.tv_sec++;
			abs_timeout.tv_nsec -= 1000000000;
		}
	}

	/* Wait until buffer available, queue is stopped or timeout */
	while (queue->used == 0 && !queue->stopped) {
		int cond_res;
		if (timeout)
			cond_res = pthread_cond_timedwait(&queue->cond,
							  &queue->mutex,
							  &abs_timeout);
		else
			cond_res = pthread_cond_wait(&queue->cond,
						     &queue->mutex);
		if (cond_res != 0) {
			res = -cond_res;
			goto out;
		}
	}

	if (queue->stopped) {
		res = -EPIPE;
		goto out;
	}

	/* Get head buffer (transfer ownership to caller) */
	*buf = queue->buffers[queue->head];
	queue->buffers[queue->head] = NULL;
	queue->head++;
	if (queue->head >= queue->depth)
		queue->head = 0;
	queue->used--;

out:
	/* No more thread waiting for data */
	queue->haswaiter = 0;

	pthread_mutex_unlock(&queue->mutex);
	return res;
}


/*
 * See documentation in public header.
 */
int mux_queue_get_buf(struct mux_queue *queue, struct pomp_buffer **buf)
{
	return mux_queue_get_buf_internal(queue, buf, NULL);
}

/*
 * See documentation in public header.
 */
int mux_queue_try_get_buf(struct mux_queue *queue, struct pomp_buffer **buf)
{
	int res = 0;
	if (queue == NULL || buf == NULL)
		return -EINVAL;

	pthread_mutex_lock(&queue->mutex);

	if (queue->stopped) {
		res = -EPIPE;
	} else if (queue->used == 0) {
		res = -EAGAIN;
	} else {
		/* Get head buffer (transfer ownership to caller) */
		*buf = queue->buffers[queue->head];
		queue->buffers[queue->head] = NULL;
		queue->head++;
		if (queue->head >= queue->depth)
			queue->head = 0;
		queue->used--;
	}

	pthread_mutex_unlock(&queue->mutex);
	return res;
}

/*
 * See documentation in public header.
 */
int mux_queue_timed_get_buf(struct mux_queue *queue,
			    struct pomp_buffer **buf,
			    struct timespec *timeout)
{
	if (timeout == NULL)
		return -EINVAL;
	return mux_queue_get_buf_internal(queue, buf, timeout);
}
