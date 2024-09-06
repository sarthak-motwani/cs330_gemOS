#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <string.h>

void tostring(char str[], unsigned long num)
{
    unsigned long i, r, len, temp;
    len = 0;
    temp = num;
    while (temp != 0)
    {
        len++;
        temp /= 10;
    }
    for (i = 0; i < len; i++)
    {
        r = num % 10;
        num = num / 10;
        str[len - (i + 1)] = r + '0';
    }
    str[len] = '\0';
}

int main(int argc, char *argv[])
{
    char *str1 = "./square";
    char *str2 = "./sqroot";
    char *str3 = "./double";
    char *endptr;

    long long temp = strtoll(argv[argc - 1], &endptr, 10);

    // checking if the last argument is negative
    if (temp < 0)
    {
        printf("Unable to execute\n");
        return 0;
    }

    unsigned long num = strtoul(argv[argc - 1], &endptr, 10);

    unsigned long y = num * num;

    if (argc > 2)
    {
        //creating arguments for the new process
        char *new_argv[argc];
        new_argv[argc - 1] = NULL;
        char temp[50] = "./";
        for (int i = 0; i < argc - 2; i++)
        {
            new_argv[i] = argv[i + 1];
        }
        strcat(temp, new_argv[0]);
        new_argv[0] = temp;
        char str[65];
        tostring(str, y);
        new_argv[argc - 2] = str;

        if (strcmp(new_argv[0], str1) && strcmp(new_argv[0], str2) && strcmp(new_argv[0], str3))
        {
            printf("Unable to execute\n");
            exit(-1);
        }

        //using exec to execute new process with remaining arguments
        if (execv(new_argv[0], (char *const *)new_argv) == -1)
        {
            printf("Unable to execute\n");
            exit(-1);
        }
    }
    else
    {
        //if no. of arguments < 2, there is no need to execute new process
        printf("%lu\n", y);
    }
    return 0;
}
