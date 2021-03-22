#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>

#ifdef __linux__
#include <ucontext.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <aio.h>
#include <regex.h>
#include <valgrind/valgrind.h>
#endif

#ifdef TARGET_OS_MAC
#define _XOPEN_SOURCE
#endif

#define handle_error(msg) \
   do { perror(msg); exit(EXIT_FAILURE); } while (0)
#define STACK_SIZE (SIGSTKSZ + 32 * 1024)

void merge_sort(int* array, int start, int end);
int* merge_arrays(int* a, int* b, int a_size, int b_size);
int* parse(char* buf, int* arr_size);

int input_count, counter;
static int* array, arr_size, *arr_size_add;

typedef enum task_state {
    READY_TO_RUN,
    RUNNING,
    TERMINATED
} task_state_t;

typedef struct task_node {
    struct task_node* prev;
    struct task_node* next;
    ucontext_t* task;
    task_state_t state;
} task_node_t;

typedef struct task_list {
    task_node_t* start;
    task_node_t* end;
    task_node_t* cur_task;
    task_node_t* finished_tasks;
    size_t task_count;
    ucontext_t main_context;
} task_list_t;

static task_node_t* init_task_node() {
    task_node_t* node = (task_node_t*) malloc(sizeof(task_node_t));
    if (!node) {
        return NULL;
    }
    node->next = node->prev = NULL;
    node->task = (ucontext_t*) calloc(1, sizeof(ucontext_t));
    if (!node->task) {
        free(node);
        return NULL;
    }
    return node;
}

static task_list_t* init_task_list() {
    task_list_t* task_list = (task_list_t*) calloc(1, sizeof(task_list_t));
    memset(&(task_list->main_context), 0, sizeof(ucontext_t));
    return task_list;
}

static task_node_t* remove_node(task_node_t* node) {
    if (!node) {
        return NULL;
    }
    if (node->next) {
        node->next->prev = node->prev;
    }

    if (node->prev) {
        node->prev->next = node->next;
    }
    node->next = NULL;
    node->prev = NULL;
    return node;
}

static void* allocate_task_stack() {
    void *stack = malloc(STACK_SIZE);
    VALGRIND_STACK_REGISTER(stack, stack + STACK_SIZE);
    stack_t ss;
    ss.ss_sp = stack;
    ss.ss_size = STACK_SIZE;
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);
    return stack;
}

static void free_node(task_node_t* node) {
    if (!node) {
        return;
    }
    if (node->task->uc_stack.ss_sp) {
        free(node->task->uc_stack.ss_sp);
    }
    free(node->task);
    free(node);
}

static void push_before(task_node_t* list, task_node_t* node) {
    if (!list || !node) {
        return;
    }
    node->prev = list->prev;
    if (node->prev) {
        node->prev->next = node;
    }
    node->next = list;
    list->prev = node;
}

static void push_after(task_node_t* list, task_node_t* node) {
    if (!list || !node) {
        return;
    }
    if (list->next) {
        list->next->prev = node;
    }
    node->next = list->next;
    list->next = node;
    node->prev = list;
}

static void push_task(task_list_t* task_list, task_node_t* node) {
    if (!task_list || !node) {
        return;
    }
    ++task_list->task_count;
    if (!task_list->start && !task_list->end) {
        task_list->start = task_list->end = node;
        return;
    }
    if (task_list->end == task_list->start) {
        push_after(task_list->start, node);
        task_list->end = node;
        return;
    }
    push_after(task_list->end, node);
    task_list->end = node;
}

static task_node_t* remove_task(task_list_t* task_list, task_node_t* node) {
    if (!task_list || !node) {
        return node;
    }
    if (node == task_list->end) {
        task_list->end = node->prev;
        node->prev = NULL;
        if (task_list->end) {
            task_list->end->next = NULL;
        }
    }
    if (node == task_list->start) {
        task_list->start = node->next;
        node->next = NULL;
        if (task_list->start) {
            task_list->start->prev = NULL;
        }
    }
    return remove_node(node);
}

static void swap_task(task_list_t* task_list) {
    task_list->cur_task->state = READY_TO_RUN;
    task_node_t* cur_task = task_list->cur_task;
    if (task_list->cur_task == task_list->start) {
        task_list->cur_task = task_list->end;
    } else {
        task_list->cur_task = task_list->cur_task->prev;
    }
    if (swapcontext(cur_task->task, task_list->cur_task->task) == -1) {
        handle_error("swapcontext");
    }
}

static void end_task(task_list_t* task_list) {
    task_list->cur_task->state = TERMINATED;
    task_node_t* cur_task = task_list->cur_task;
    if (cur_task == task_list->start) {
        cur_task = task_list->end;
    } else {
        cur_task = cur_task->prev;
    }
    task_node_t* finished_task = remove_task(task_list, task_list->cur_task);
    if (task_list->finished_tasks) {
        push_before(task_list->finished_tasks, finished_task);
    }
    task_list->finished_tasks = finished_task;
    --task_list->task_count;
    task_list->cur_task = cur_task;
}

static void gc_collect(task_list_t* task_list) {
    if (!task_list) {
        return;
    }
    while (task_list->finished_tasks) {
        task_node_t* iter = task_list->finished_tasks;
        task_list->finished_tasks = iter->next;
        free_node(iter);
    }
}

static void run_tasks(task_list_t* task_list) {
    if (!task_list) {
        return;
    }
    task_list->cur_task = task_list->end;
    while (task_list->task_count > 0) {
        if (swapcontext(&task_list->main_context, task_list->cur_task->task) == -1) {
            handle_error("swapcontext");
        }
        gc_collect(task_list);
    }
}

static void free_task_list(task_list_t* task_list) {
    if (!task_list) {
        return;
    }
    gc_collect(task_list);
    task_node_t* iter = task_list->start;
    while (iter != NULL) {
        task_node_t* tmp = iter;
        iter = iter->next;
        free_node(tmp);
    }
    free(task_list);
}

static void add_task(task_list_t* task_list, void (*task_async) (task_list_t*, int), int fd)
{
    task_node_t* node = init_task_node();
    if (!node) {
        return;
    }
    push_task(task_list, node);
    if (getcontext(node->task) == -1) {
        handle_error("getcontext");
    }
    void *tmp_stack = allocate_task_stack();
    if (!tmp_stack) {
        return;
    }
    node->task->uc_stack.ss_sp = tmp_stack;
    node->task->uc_stack.ss_size = STACK_SIZE;
    node->task->uc_link = &(task_list->main_context);
    node->state = RUNNING;
    makecontext(node->task, (void (*)(void)) task_async, 2, task_list, fd);
}

void output_write(const char* output_name) {
    int i = 0, offset = 0;
    size_t size = arr_size * 12;
    char* buffer = malloc(size * sizeof(char));
    char* str = buffer;
    while (i < arr_size)
    {
        sprintf(str, "%d %n", array[i++], &offset);
        str += offset;
    }
    *str = '\0';
    size = strlen(buffer);

    int fd = open(output_name, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if(fd < 0) {
        printf("Error: can't open file\n");
        free(buffer);
        return;
    }
    size_t write_bytes = write(fd, buffer, size);
    if(write_bytes < 0) {
        printf("Error: can't write file\n");
        free(buffer);
        return;
    }
    if(close(fd) != 0) {
        printf("Error: can't close file\n");
        free(buffer);
        return;
    }
    free(buffer);
}

void task_async(task_list_t* task_list, int fd) {

    struct stat statbuf = {};
    if (fstat(fd, &statbuf) == -1) {
        return;
    }
    swap_task(task_list);
    
    char* buf = (char*) malloc(sizeof(char) * statbuf.st_size + 1);
    if (!buf) {
        return;
    }
    swap_task(task_list);

    struct aiocb cb = {
        .aio_fildes = fd,
        .aio_buf = buf,
        .aio_offset = lseek(fd, 0, SEEK_CUR),
        .aio_nbytes = statbuf.st_size,
    };
    aio_read(&cb);
    swap_task(task_list);

    int c = 0;
    while ((c = aio_error(&cb)) == EINPROGRESS) {
        swap_task(task_list);
    }
    int read_bytes = aio_return(&cb);
    int* arr = parse(buf, &arr_size);
    free(buf);
    swap_task(task_list);

    arr_size_add[counter] = arr_size;
    merge_sort(arr, 0, arr_size - 1);
    counter++;
    swap_task(task_list);

    int* array_tmp;
    if (counter == input_count) {
        array = arr;
        arr_size = arr_size_add[counter - input_count];
    }
    else {
        array_tmp = merge_arrays(array, arr, arr_size, arr_size_add[counter - input_count]);
        arr_size += arr_size_add[counter - input_count];
        array = array_tmp;
    }
    counter++;
    swap_task(task_list);

    if (counter == input_count * 2) {
        output_write("test.txt");
    }
    swap_task(task_list);

    free(arr);
    end_task(task_list);
}

void merge_sort(int* array, int start, int end) {
    if (end - start < 1)
        return;
    int middle = start + (end - start) / 2;
    merge_sort(array, start, middle);
    merge_sort(array, middle + 1, end);

    int size = end + 1;
    int* tmp = malloc(size * sizeof(int));
    if(!tmp)
        return;
    for (int k = start; k <= end; ++k)
    {
        tmp[k] = array[k];
    }
    int i = start, j = middle + 1;
    for (int k = start; k <= end; ++k)
    {
        if (i > middle) {
            array[k] = tmp[j];
            ++j;
        } else if (j > end) {
            array[k] = tmp[i];
            ++i;
        } else if (tmp[j] < tmp[i]) {
            array[k] = tmp[j];
            ++j;
        } else {
            array[k] = tmp[i];
            ++i;
        }
    }
    free(tmp);
}

int* merge_arrays(int* a, int* b, int a_size, int b_size){
    int i = 0, j = 0, k = 0;
    int* res = malloc((a_size + b_size) * sizeof(int));
    while((i < a_size) || (j < b_size)) {
        if(i == a_size)
            res[k++] = b[j++];
        else if(j == b_size)
            res[k++] = a[i++];
        else
            res[k++] = (a[i] < b[j]) ? a[i++] : b[j++];
    }
    return res;
}

int* parse(char* buf, int* arr_size) {
    int* arr = malloc(10 * sizeof(int));
    if(!arr)
        return NULL;
    char* str = buf;
    int i = 0, offset = 0;
    while(sscanf(str, "%d%n", &arr[i], &offset) == 1) {
        str += offset;
        ++i;
        if(i % 10 == 9) {
            int* p = realloc(arr, (i + 11) * sizeof(int));
            if(!p)
                return NULL;
            else
                arr = p;
        }
    }
    *arr_size = i;
    return arr;
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        printf("Usage: task_1 \"test_1.txt\" \"test_2.txt\" \"test_3.txt\" \n");
        printf("P.S. Compile with '-lrt' flag\n");
        return 0;
    }
    printf("Default output: \"test.txt\" \n");

    int* input_array = calloc(argc, sizeof(int));
    regex_t regex;
    int reti = regcomp(&regex, ".txt", 0);
    for (int i = 1; i < argc; ++i)
    {
        reti = regexec(&regex, argv[i], 0, NULL, 0);
        if (reti == 0) {
            input_count++;
            input_array[i]++;
        }
    }
    regfree(&regex);

    int* fd = malloc(argc * sizeof(int));
    arr_size_add = malloc(input_count * sizeof(int));

    int* valgrind_ret = malloc(input_count*sizeof(int));

    task_list_t* task_list = init_task_list();
    if (!task_list) {
        return -1;
    }
    for (int i = 1; i < argc; ++i) {
        if (input_array[i] == 1) {
            fd[i] = open(argv[i], O_RDONLY);
            if (fd < 0) {
                printf("Couldn't open file: \"%s\"\n", argv[i]);
                return -1;
            }
            add_task(task_list, task_async, fd[i]);
        } 
    }
    run_tasks(task_list);
    free_task_list(task_list);

    for (int i = 1; i < argc; ++i) {
        if (input_array[i] == 1) {
            close(fd[i]);
        }
    }
    VALGRIND_STACK_DEREGISTER(valgrind_ret);
    free(valgrind_ret);
    free(arr_size_add);
    free(array);
    free(fd);

    printf("Finished!\n");
    return 0;
}
