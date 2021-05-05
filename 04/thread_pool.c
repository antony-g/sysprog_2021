#include "thread_pool.h"

typedef struct thread_task {
	thread_task_f function;
	pthread_cond_t cond;
	pthread_mutex_t lock;
	void* arg;
	void* result;
	bool in_pool;
	bool is_joined;
	bool is_finished;
} thread_task_t;

typedef struct task_list {
	thread_task_t** data;
	int size;
	int capacity;
} task_list_t;

typedef struct thread_pool {
	pthread_t* threads;
	pthread_cond_t cond;
	pthread_mutex_t lock;
	task_list_t* task_list;
	int count;
	int active;
	int max_thread_count;
	bool is_finished;
} thread_pool_t;

int thread_pool_thread_count(const thread_pool_t *pool) {
	return pool->count;
}

bool thread_task_is_running(const thread_task_t *task) {
	return task->in_pool;
}

bool thread_task_is_finished(const thread_task_t *task) {
	return task->is_finished;
}

void task_free(thread_task_t* task) {
	pthread_mutex_destroy(&task->lock);
	pthread_cond_destroy(&task->cond);
	free(task);
}

void* allocate(void* p, int size) {
	void* tmp = realloc(p, size);
	if (!tmp) {
		handle_error("realloc");
	}
	return tmp;
}

void gc_collect(void* tpool, void* tasks, void* threads) {
	free(tpool);
	free(tasks);
	free(threads);
}


int thread_pool_new(int max_thread_count, thread_pool_t **pool) {
	static int error_1, error_2;
	if (max_thread_count <= 0 || max_thread_count > TPOOL_MAX_THREADS) {
		return TPOOL_ERR_INVALID_ARGUMENT;
	}
	thread_pool_t* tpool = allocate(NULL, sizeof(thread_pool_t));
	pthread_t* threads = allocate(NULL, max_thread_count * sizeof(pthread_t));
	task_list_t* tasks = allocate(NULL, sizeof(task_list_t));
	tasks->capacity = tasks->size = 0;
	tpool->count = tpool->active = 0;
	tasks->data = NULL;
	tpool->max_thread_count = max_thread_count;
	tpool->threads = threads;
	tpool->task_list = tasks;

	error_1 = pthread_cond_init(&tpool->cond, NULL);
	if (error_1) {
		gc_collect(tpool, tasks, threads);
		return -1; 
	}
	error_2 = pthread_mutex_init(&tpool->lock, NULL);
	if (error_2) {
		gc_collect(tpool, tasks, threads);
		return -1; 
	}
	tpool->is_finished = false;
	*pool = tpool;
	return 0;
}

int thread_pool_delete(thread_pool_t *pool)
{
	pthread_mutex_lock(&pool->lock);
	if (pool->task_list->size || pool->active) {
		pthread_mutex_unlock(&pool->lock);
		return TPOOL_ERR_HAS_TASKS;
	}
	pool->is_finished = true;
	pthread_cond_broadcast(&pool->cond);
	pthread_mutex_unlock(&pool->lock);

	for (int i = 0; i < pool->count; ++i) {
		pthread_join(pool->threads[i], NULL);
	}
	free(pool->threads);
	free(pool->task_list->data);
	free(pool->task_list);
	pthread_cond_destroy(&pool->cond);
	pthread_mutex_destroy(&pool->lock);
	free(pool);
	return 0;
}

task_list_t* resize_task(task_list_t* tasks) {
	if (tasks->size >= tasks->capacity) {
		int cap = (tasks->capacity + 1) * 2;
		int size = cap * sizeof(thread_task_t*);
		thread_task_t** data = allocate(tasks->data, size);
		tasks->data = data; 
	}
	return tasks;
}

int thread_task_new(thread_task_t **task, thread_task_f function, void *arg) {
	thread_task_t* tmp = allocate(NULL, sizeof(thread_task_t));
	tmp->function = function;
	tmp->arg = arg;
	tmp->in_pool = false;
	tmp->is_joined = false;
	tmp->is_finished = false;
	int error = pthread_cond_init(&tmp->cond, NULL);
	if (error) {
		free(tmp);
		return -1;
	}
	error = pthread_mutex_init(&tmp->lock, NULL);
	if (error) {
		pthread_cond_destroy(&tmp->cond);
		free(tmp);
		return -1;
	}
	*task = tmp;
	return 0;
}

int thread_task_join(thread_task_t *task, void **result) {
	if (!task->in_pool) {
		return TPOOL_ERR_TASK_NOT_PUSHED;
	}
	pthread_mutex_lock(&task->lock);
	while (!task->is_finished) {
		pthread_cond_wait(&task->cond, &task->lock);
	}
	*result = task->result;
	task->is_joined = true;
	pthread_mutex_unlock(&task->lock);
	return 0;
}

/* реализовать таймаут для thread_task_join() */

int thread_task_join_timeout(thread_task_t *task, void **result, double timeout) {
	static int tmp;
	struct timespec timer;
	if (!task->in_pool) {
		return TPOOL_ERR_TASK_NOT_PUSHED;
	}
	clock_gettime(CLOCK_REALTIME, &timer);
	timer.tv_sec += timeout;
	pthread_mutex_lock(&task->lock);
	while (!task->is_finished && !tmp) {
		tmp = pthread_cond_timedwait(&task->cond, &task->lock, &timer);
	}
	if (tmp) {
		pthread_mutex_unlock(&task->lock);
		return TPOOL_ERR_TIMEOUT;
	}
	*result = task->result;
	task->is_joined = true;
	pthread_mutex_unlock(&task->lock);
	return 0;
}

thread_task_t* swap_task(thread_pool_t* pool) {
	task_list_t* tq = pool->task_list;
	return tq->data[--tq->size];
}

void* run_task(void* thread) {
	thread_pool_t* pool = (thread_pool_t*) thread;
	for (;;) {
		pthread_mutex_lock(&pool->lock);
		while (!pool->task_list->size && !pool->is_finished) {
			pthread_cond_wait(&pool->cond, &pool->lock); 
		}
		if (pool->is_finished) {
			pthread_mutex_unlock(&pool->lock);
			break;
		}

		thread_task_t* task = swap_task(pool);
		pool->active += 1;
		pthread_mutex_unlock(&pool->lock);
		task->result = task->function(task->arg);
		pthread_mutex_lock(&task->lock);
		task->is_finished = true;
		
		pthread_mutex_lock(&pool->lock);
		pool->active -= 1;
		pthread_cond_signal(&task->cond);
		pthread_mutex_unlock(&task->lock);
		pthread_mutex_unlock(&pool->lock);
	}
}

int thread_pool_push_task(thread_pool_t *pool, thread_task_t *task) {
	pthread_mutex_lock(&pool->lock);
	task_list_t* tasks = resize_task(pool->task_list);
	tasks->data[tasks->size++] = task;
	task->in_pool = true;
	task->is_joined = false;
	task->is_finished = false;
	if (pool->count == pool->active && pool->count < pool->max_thread_count) {
		pthread_create(&pool->threads[pool->count++], NULL, run_task, pool);
	}
	pthread_cond_signal(&pool->cond);
	pthread_mutex_unlock(&pool->lock);
	return 0;
}

int thread_task_delete(thread_task_t *task) {
	if (!task->in_pool) {
		task_free(task);
		return 0;
	}
	pthread_mutex_lock(&task->lock);
	if (!(task->is_joined && task->is_finished)) {
		pthread_mutex_unlock(&task->lock);
		return TPOOL_ERR_TASK_IN_POOL;
	}
	pthread_mutex_unlock(&task->lock);
	task_free(task);
	return 0;
}

/* Реализовать функцию detach */

#ifdef NEED_DETACH

int thread_task_detach(thread_task_t *task) {
	pthread_mutex_lock(&task->lock);
	task->is_joined = true;
	pthread_mutex_unlock(&task->lock);
	return 0;
}

#endif
