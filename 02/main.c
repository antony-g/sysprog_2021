/*
	Welcome to the Linux terminal emulator.
	To start: enter something (Type 'exit' or 'quit' to stop).
	Compile with 'make' in console.");
*/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>

#ifdef __linux__
#include <sys/wait.h>
#endif

#ifdef TARGET_OS_MAC
#define _XOPEN_SOURCE
#endif

#include "main.h"

int (*copy)(int, int) = dup2;
void free_task(Task_t* task);

void init_node()
{
    root->next = root;
}

void push_node(pid_t pid, Task_t* task)
{
    Node_t* node;
    if (!pid || !task) {
        return;
    }
    Node_t* p = malloc(sizeof(Node_t));
    if (!p) {
    	handle_error("Bad memory allocation!\n");
    } else {
        node = (Node_t*) p;
    }
    node->pid = pid;
    node->task = task;
    node->next = root->next;
    root->next = node;
    assert(node);
}

void remove_node(pid_t pid)
{
    if (!pid) {
        return;
    }
    Node_t* node = root;
    Node_t* tmp = root->next;
    while (tmp->pid != pid && tmp != root) {
        node = tmp;
        tmp = tmp->next;
    } 
    if (tmp == root) {
        return;
    }
    node->next = tmp->next;
    free_task(tmp->task);
    free(tmp);
}

void free_node()
{
    Node_t* node = root->next;
    if (node != root) {
        while (root->next != root) {
            root->next = node->next;
            free(node);
            node = root->next;
        }
        free_task(node->task);
    }
}

void alloc_exec()
{ 
    ++exe->argc;
    if (exe->argv != NULL) {
        char* p = realloc(exe->argv, sizeof(char*) * (exe->argc + 1));
        if (!p) {
        	handle_error("Bad memory allocation!\n");
        } else {
            exe->argv = (char**) p;
        }
    } else {
        char* p = malloc(2 * sizeof(char*));
        if (!p) {
            free(exe->argv);
        	handle_error("Bad memory allocation!\n");
        } else {
            exe->argv = (char**) p;
        }
    }
    assert(exe->argv);

    if (exe->size != NULL) {
        size_t* p = realloc(exe->size, sizeof(size_t) * (exe->argc + 1));
        if (!p) {
            free(exe->argv);
        	handle_error("Bad memory allocation!\n");
        } else {
            exe->size = (size_t*) p;
        } 
    } else {
        char* p = malloc(2 * sizeof(char));
        if (!p) {
            free(exe->argv);
            free(exe->size);
        	handle_error("Bad memory allocation!\n");
        } else {
            exe->size = (size_t*) p;
        }
    }
    assert(exe->size);

    char* p = malloc(2 * sizeof(char));
    if (!p) {
        free(exe->argv);
        free(exe->size);
    	handle_error("Bad memory allocation!\n");
    } else {
        exe->size[exe->argc - 1] = 0;
        exe->argv[exe->argc - 1] = (char*) p;
    }
    assert(exe->argv[exe->argc - 1]);
}

void push_exec(char c)
{
    if (!c) {
        return;
    }
    if (exe->argc == 0)
        alloc_exec();
    size_t pos = exe->size[exe->argc - 1];
    char* p = realloc(exe->argv[exe->argc - 1], pos + 2);
    if (!p) {
    	handle_error("Bad memory allocation!\n");
    } else {
        exe->argv[exe->argc - 1] = p;
    }
    assert(exe->argv[exe->argc - 1]);

    exe->argv[exe->argc - 1][pos] = c;
    exe->argv[exe->argc - 1][pos + 1] = 0;
    ++exe->size[exe->argc - 1];
}

void push_operator(Operator_t op)
{ 
    if (cur_task->ops) {
    	Operator_t* p = realloc(cur_task->ops, sizeof(Operator_t) * (cur_task->n_cmds + 1));
    	if (!p) {
    		handle_error("Bad memory allocation!\n");
    	} else {
        	cur_task->ops = p;
    	}
    } else {
    	Operator_t* p = malloc(sizeof(Operator_t) * 2);
    	if (!p)
    	{
    		handle_error("Bad memory allocation!\n");
    	} else {
        	cur_task->ops = p;
    	}
    }
    assert(cur_task->ops);
    cur_task->ops[cur_task->n_cmds - 1] = op;
    cur_task->ops[cur_task->n_cmds] = NONE;
}

void push_cmd()
{ 
    if (!exe->size)
        return;
    if (exe->size[exe->argc - 1] == 0)
    {
        --exe->argc;
        free(exe->argv[exe->argc]); 
        exe->argv[exe->argc] = NULL;
    }

    ++cur_task->n_cmds;
    if (cur_task->n_cmds >= 2) {
        Exec_t* p = realloc(cur_task->cmds, sizeof(Exec_t) * (cur_task->n_cmds + 1));
        if (!p) {
        	handle_error("Bad memory allocation!\n");
        } else {
        cur_task->cmds = p;
    	}
    } else {
    	Exec_t* p = malloc(sizeof(Exec_t));
    	if (!p)	{
    		handle_error("Bad memory allocation!\n");
    	} else {
        	cur_task->cmds = p;
    	}
    }
    assert(cur_task->cmds);
    memcpy(&cur_task->cmds[cur_task->n_cmds - 1], &exe, sizeof(Exec_t));
    memset(&exe, 0, sizeof(Exec_t));
}

void parse_operator(char c)
{ 
    char next;
    static char mark;
    static _Bool indent = TRUE;

    switch(c) {
    case ' ':
        if (!is_str && !indent) {
            alloc_exec();
            indent = 1;
            return; 
        } else if (indent == TRUE) {
            return;
        }
    break;

    case '\'':
        if (is_str && mark == '\"') {
            push_exec(c);
            return;
        }
    break;

    case '\\':
        c = getchar();
        if (c != '\n') {
            push_exec(c);
        }
        return;
    break;

    case '|':
        next = getchar();
        if (next != '|') {
            ungetc(next, stdin);
        }
        push_cmd();
        if (next == '|') {
        	push_operator(OR);
        } else {
        	push_operator(PIPE);
        }
        return;
    break;

    case '&':
        next = getchar();
        if (next != '&') {
            cur_task->is_bg = TRUE;
            ungetc(next, stdin);
               return;
        }
        push_cmd();
        push_operator(AND);
        return;
    break;
    }

    if (is_str) {
        if (mark == c) {
            mark = FALSE;
            is_str = FALSE;
            return;
        }
    } else {
        if (quote(c)) {
            mark = c;
            is_str = TRUE;
            return;
        }
    }
    indent = (c == ' ' && !is_str);
    push_exec(c);
}

void handle_exit(size_t argc, char** argv)
{
    if (!strcmp(argv[0], "exit") || !strcmp(argv[0], "quit"))
    {
        size_t exit_code = 0;
        switch(argc)
        {
            case 1:
                exit(EXIT_SUCCESS);
            break;
            case 2:
                sscanf(argv[1], "%lu", &exit_code);
                exit(exit_code);
            break;
            default:
                exit(EXIT_FAILURE);
            break;
        }
    }
    if (!strcmp(argv[0], "true")) {
        exit(EXIT_SUCCESS);
    }
    if (!strcmp(argv[0], "false")) {
        exit(EXIT_FAILURE);
    }
}

void init_cmd()
{ 
    int* p = memset(&cur_task, 0x00, sizeof(Task_t));
    if (!p) {
    	handle_error("Bad memory allocation!\n");
    }
    alloc_exec();
    char c = 0;
    #define CLEAR_STDIN { while (getchar() != '\n'); break; }
    while ((c = getchar()) != '\n' || is_str)
    {
        if (c == EOF) {
            is_eof = TRUE;
            return;
        }
        if (c == '#') {
            CLEAR_STDIN;
        }
        parse_operator(c);
        if (cur_task->is_bg) {
            CLEAR_STDIN;
        }
    }
    #undef CLEAR_STDIN
    parse_operator(' ');
    push_cmd(); 
}

void free_cmd(Exec_t cmd)
{
    free(cmd.size);
    for (size_t i = 0; i < cmd.argc; ++i) {
        free(cmd.argv[i]);
    }
    free(cmd.argv);
}

Task_t* parse_task()
{
    init_cmd();
	Task_t *result, *p;
    p = malloc(sizeof(Task_t));
    if (!p) {
    	handle_error("Bad memory allocation!\n");
    } else {
    	result = p;
    }
    assert(result);

    *result = *cur_task;
    p = memset(&cur_task, 0, sizeof(Task_t));
    if (!p)
    {
    	handle_error("Bad memory allocation!\n");
    }
    return result;
}

void free_task(Task_t* task)
{
    if (!task) {
    	return;
    }
    free(task->ops);
    for (size_t i = 0; i < task->n_cmds; ++i) {
        free_cmd(task->cmds[i]);
    }
    free(task->cmds);
    free(task);
}

unsigned char parse_par(Exec_t cmd, Operator_t cur_oper)
{
    if (cur_oper != PIPE && cmd.argc > 2)
    {
        unsigned short int operator = cmd.argv[cmd.argc - 2][0] << sizeof(unsigned short int) | cmd.argv[cmd.argc - 2][1];
        switch(operator)
        {
            case (('>' << sizeof(unsigned short int)) | '\0'):
                return 1;
            break;
            
            case (('>' << sizeof(unsigned short int)) | '>'):
                return 2;
            break;
        
            default:
                return -1;
            break;
        }
    }
    return -1;
}

void exec(Exec_t cmd, int file_in, int file_out, int file_err)
{
    istream(file_in);
    ostream(file_out);
    estream(file_err);
    handle_exit(cmd.argc, cmd.argv);

    char** argv;
    char** ptr =  calloc(cmd.argc + 1 - 2 * is_file, sizeof(char*));
    if (!ptr) {
    	handle_error("Bad memory allocation!\n");
    } else {
    	argv = ptr;
    }
    assert(argv);

    char* p = memcpy(argv, cmd.argv, sizeof(char*) * (cmd.argc - 2 * is_file));
    if (!p) {
    	handle_error("Bad memory allocation!\n");
    }
    execvp(argv[0], argv); // execvp
    perror("Exec method error!\n");
    return;
}

int execute(Exec_t cmd, Operator_t cur_oper, Operator_t prev_oper)
{
    Pipe_t cur_pipe;

    if (!strcmp(cmd.argv[0], "cd"))
    {
        if (cmd.argc == 2) {
            DIR* path = opendir(cmd.argv[1]);
            check_path(path);
            return 0;
        } else {
            handle_error("Exec command error!\n");
        }
    }
    check_exec(cmd.argv[0]);
    int flag, flags;
    char output = parse_par(cmd, cur_oper); 
    if (output >= 0) {
    	if (output == 2) {
    		flag = O_APPEND;
    	} else {
    		flag = O_TRUNC;
    	}
        flags = O_CREAT | O_RDWR | flag;
        cur_ofstream = open(cmd.argv[cmd.argc - 1], flags, S_IWUSR | S_IRUSR);
        free(cmd.argv[cmd.argc - 2]);
        cmd.argv[cmd.argc - 2] = NULL;
    }
    if (cur_oper == PIPE) {
        if (pipe((int*) &cur_pipe) < 0) {
            handle_error("Undead method error!\n");
        }
        cur_ofstream = cur_pipe.fd_write;
    }

    pid_t pid = fork();
    if (!pid) {
        exec(cmd, cur_ifstream, cur_ofstream, STDERR_FILENO);
    } else {
        wait(&e);
    }
    close_stream(cur_ifstream, STDIN_FILENO);
    close_stream(cur_ofstream, STDOUT_FILENO);
    cur_ifstream = cur_pipe.fd_read;
    return WEXITSTATUS(e);
}

void exec_task(Task_t* task)
{
    if (!task) {
        return;
    }
    if ((!task->ops && task->n_cmds >= 2) || !task->cmds) {
        return;
    }
    size_t n_cmds = task->n_cmds;
    Operator_t cur = NONE, prev = NONE;
    Operator_t* ops = task->ops;
    Exec_t* cmds = task->cmds;
    _Bool error = !task->cmds->size[0];
    for (size_t i = 0; i < n_cmds && !error; ++i) {
    	if (i == n_cmds - 1) {
        	cur =  NONE;
    	} else {
    		cur = ops[i];
    	}
        ex_code = execute(cmds[i], cur, prev);
        if (cur == AND && ex_code) {
            break;
        } else if (cur == OR && !ex_code) {
            while (i < n_cmds - 1 && ops[i] == OR && ++i);
        }
        prev = cur;
    }
}

void handle_fork(int sig)
{
    pid_t pid;
    int status = 0;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        ++n_process_undead;
        if (write(pipe_undead.fd_write, &pid, sizeof(pid)) == -1) {
            handle_error("Handle fork method error!\n");
        }
    }
}

void sigact() {
	struct sigaction sig;
    sig.sa_handler = &handle_fork;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    if (sigaction(SIGCHLD, &sig, 0) < 0) {
        handle_error("Sigaction method error!\n");
    }
}

void kill_undead()
{
    pid_t pid = 0;
    while (n_process_undead > 0)
    {
    	pid = 0;
        if (read(pipe_undead.fd_read, &pid, sizeof(pid)) != sizeof(pid)) {
            handle_error("Kill undead method error!\n");
        }
        remove_node(pid);
        --n_process_undead;
        if (n_process_bg) {
            --n_process_bg;
        }
    }
}

void run_task(pid_t pid, Task_t* task) {
	if (!pid) {
        exec_task(task);
        exit(EXIT_SUCCESS);
    } else if (pid < 0) {
        handle_error("Fork creation method error!\n");
    }
    ++n_process_bg;
    push_node(pid, task);
}

int main(int argc, char* argv[])
{
    if (pipe((int*) &pipe_undead) < 0) {
        handle_error("Undead pipe method error!\n");
    }
    sigact();
    init_node();
    while (TRUE)
    {
        Task_t* new_task = parse_task();
        assert(new_task);
        if (new_task->is_bg)
        {
            pid_t pid = fork();
            run_task(pid, new_task);
            continue;
        }
        exec_task(new_task);
        free_task(new_task);
        kill_undead();
        if (is_eof) {
            break;
        }
    }

    while (n_process_bg > 0) {
        kill_undead();
    }
    free_node();
    close(pipe_undead.fd_read);
    close(pipe_undead.fd_write);
    return 0;
}
