#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{

    char messageChar[] = "oacerdspmn";
    char messageHexa[(2 * strlen(messageChar)) + 1]; //6f 61 63 65 72 64 73 70 6d 6e
    messageHexa[strlen(messageHexa) - 1] = '\0';

    int i = 0; //Controla char
    int j = 0; //Controla hexa

    while (messageChar[i] != '\0')
    {
        sprintf((messageHexa + j), "%02x", messageChar[i]);
        i++;
        j += 2;
    }

    printf("%s", messageHexa);

    return 0;
}