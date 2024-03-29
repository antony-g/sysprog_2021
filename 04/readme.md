# Домашнее задание №4 
## Пул потоков (Thread pool)

### Задание

Нужно реализовать пул потоков. В разных программах, выполняющих
много независимых и легко распараллеливаемых задач часто бывает
удобно разносить их по разным потокам. Но создавать поток на
каждую необходимость что-то вынести в него довольно дорого по
времени и ресурсам. Если задача не слишком долгая, не читает диск,
сеть, то создание/удаление потока может занять больше времени, чем
сама задача.

Тогда обычно либо задачи вообще не параллелят, либо при их большом
количестве создают пул потоков. Это такой резерв рабочих потоков,
который имеет очередь задач и некое число потоков, которые с
очереди задачи забирают. Таким образом, можно всегда иметь под
рукой уже созданный поток, который может быстро подхватить любую
задачу, а в конце вместо завершения возьмет следующую.

В библиотеках часто есть уже готовое решение: в __Qt__ это класс
`QThreadPool`, в __.NET__ это класс `ThreadPool`, в __boost__ это
класс `thread_pool`. В задании нужно реализовать свое, подобное.

В файлах __thread_pool.h__ и __thread_pool.c__ можно найти шаблоны
функций и структур, которые надо реализовать.

Пул потоков описывается структурой `struct thread_pool`,
реализованной в __thread_pool.c__, а у пользователя может быть на нее
только указатель. Каждая задача аналогично описывается структурой
`struct thread_task`, которые пользователь может создавать и класть
в пул в очередь.

Пользователь может проверять состояние задачи (ждет постановки в
поток; уже в потоке и выполняется), можно дождаться ее завершения
и получить результат при помощи `thread_task_join`, наподобие
`pthread_join`.

В решении нужно обратить внимание, что `thread_pool` при создании
через `thread_pool_new` не должен сразу стартовать все потоки.
Потоки должны создаваться по мере необходимости, пока не достигнут
лимита, заданного пользователем в `thread_pool_new`.

### Тестирование

Поскольку задача - реализация библиотеки, то программы __main__ нет,
а значит и принимать на вход некуда. Вы можете писать тесты на С,
в отдельном файле, где будет __main__, и куда будет делаться __include__
вашего решения. Например, создается файл __main.c__, который делает
`include "thread_pool.h"` и в функции __main__ делает какие-то тесты.

Это все собирается так:
```
        gcc thread_pool.c main.c
```

### Реализация

- 15 баллов: реализовать все функции из __thread_pool.h__, как описано
  выше и в самом файле.

- +5 баллов: реализовать функцию detach. В __thread_pool.h__ уже
  определена функция detach под макросом __NEED_DETACH__.

- +5 баллов: реализовать таймаут для `thread_task_join()`:

```C
  int thread_task_join(struct thread_task *task, double timeout, void **result);
  // Таймаут здесь в секундах. Эта функция должна начать возвращать новый код ошибки: TPOOL_ERR_TIMEOUT.
```

Добавочные пункты на +5 баллов друг друга не включают. То есть
можно не делать ни одного, можно сделать первый, или второй, или
оба для +10.
