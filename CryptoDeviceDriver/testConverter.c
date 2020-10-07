#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{

    char messageChar[] = "oededfsafsd";
    char messageChar2[strlen(messageChar)];
    char messageHexa[(2 * strlen(messageChar)) + 1];
    messageHexa[strlen(messageHexa) - 1] = '\0';

    int i = 0; //Controla char
    int j = 0; //Controla hexa

    //Char para hexa
    while (messageChar[i] != '\0')
    {
        sprintf((messageHexa + j), "%02x", messageChar[i]);
        i++;
        j += 2;
    }

    printf("%s", messageHexa);
    printf("\n");

    //Hexa para char
    i = 0;
    j = 0;
    char temp[3];
    int num;
    for (j = 0; j < strlen(messageHexa) + 1; j += 2)
    {
        sprintf(temp, "%c%c", messageHexa[j], messageHexa[j + 1]);
        num = (int)strtol(temp, NULL, 16);
        messageChar2[i] = (char)num;
        i++;
    }

    printf("%s", messageChar2);

    return 0;
}
