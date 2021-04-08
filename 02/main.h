#ifndef MAIN_H
#define MAIN_H

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define assert(ptr) \
if(!ptr) { perror("nullptr"); exit(EXIT_FAILURE); }

#define TRUE 1
#define FALSE 0

int e;
int ex_code;
static _Bool is_eof, is_str, is_file;

size_t n_process_bg, n_process_undead;
int cur_ifstream = STDIN_FILENO;
int cur_ofstream = STDOUT_FILENO;

typedef enum Operator
{
    PIPE,
    OR,
    AND,
    NONE,
} Operator_t;

typedef struct Node
{
    pid_t pid;
    struct Task* task;
    struct Node* next;
} Node_t;
static Node_t root[3];

typedef struct Pipe
{
    int fd_read;
    int fd_write;
} Pipe_t;
static Pipe_t pipe_undead;

typedef struct Exec
{
    size_t* size;
    size_t argc;
    char** argv;
} Exec_t;
static Exec_t exe[3];

typedef struct Task
{
    size_t n_cmds;
    Operator_t* ops;
    Exec_t* cmds;
    _Bool is_bg;
} Task_t;
static Task_t cur_task[4];

#define quote(c) ( c == '\"' || c == '\'')

#define istream(file_in) if(file_in != STDIN_FILENO) { copy(file_in, STDIN_FILENO); close(file_in); }

#define ostream(file_out) if(file_out != STDOUT_FILENO) { copy(file_out, STDOUT_FILENO); close(file_out); }

#define estream(file_err) if(file_err != STDERR_FILENO) { copy(file_err, STDERR_FILENO); close(file_err); }

#define close_stream(stream, stdin) if(stream != stdin) close(stream);

#define check_path(path) \
if (path == 0 && ENOENT == errno) { printf("Opendir method error!\n"); } else if (chdir(cmd.argv[1])) { handle_error("Chdir method error!\n"); } closedir(path);

#define check_exec(arg) \
if((!strcmp(arg, "exit") || !strcmp(arg, "quit")) && prev_oper == NONE && cur_oper == NONE) { exit(EXIT_SUCCESS); } \
    if(prev_oper != PIPE) { cur_ifstream = STDIN_FILENO; } \
    if(cur_oper != PIPE) { cur_ofstream = STDOUT_FILENO; }

#endif
