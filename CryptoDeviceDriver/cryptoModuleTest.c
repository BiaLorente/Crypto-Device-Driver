#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <stdio_ext.h>

#define BUFFER_LENGTH 256           ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH]; ///< The receive buffer from the LKM

void clearMessage(char[]);
void clearScreen();
void printHexDump(const void *, int, int);
void hexToAscii(char[], char[]);

int main()
{
    setlocale(LC_ALL, "Portuguese");

    int ret, fd;
    int option1, option2;
    char messageToSend[BUFFER_LENGTH + 2];
    char messageAscii[BUFFER_LENGTH + 2];

    if ((fd = open("/dev/crypto", O_RDWR)) < 0)
    {
        perror("Failed to open the device...");
        return errno;
    }

    do
    {

        clearMessage(messageToSend);
        clearMessage(receive);
        clearMessage(messageToPrint);
        clearMessage(messageAscii);

        do
        {
            clearScreen();
            printf("====================\n");
            printf("1.Cifrar mensagem\n");
            printf("2.Decifrar mensagem\n");
            printf("3.Resumo criptográfico\n");
            printf("0.Sair\n");
            printf("====================\n");
            printf("Digite a opção desejada: ");
            scanf("%d", &option2);
            getchar();

        } while (option2 < 0 || option2 > 3);

        switch (option2)
        {
        case 0:

            return 0;
            break;

        case 1: //Cifrar

            clearScreen();
            printf("Digite a mensagem para ser cifrada: ");
            scanf("%[^\n]%*c", messageToSend);
            printf("\nString enviada: %s\n", messageToSend);
            strcat(messageToSend, " c");

            if ((ret = write(fd, messageToSend, strlen(messageToSend))) < 0)
            {
                perror("Falha ao enviar mensagem");
                return errno;
            }

            printf("\nPressione ENTER para ler a resposta\n");
            getchar();

            if ((ret = read(fd, receive, BUFFER_LENGTH)) < 0)
            {
                perror("Falha ao ler resposta");
                return errno;
            }

            printf("Mensagem cifrada: ");
            printHexDump(receive, option2, 16);
            printf("\n\nPressione ENTER para continuar\n");
            getchar();

            break;

        case 2: //Decifrar

            clearScreen();
            printf("Digite a mensagem para ser decifrada: ");
            scanf("%[^\n]%*c", messageToSend);
            printf("\nMensagem Enviada: %s\n", messageToSend);
            hexToAscii(messageToSend, messageAscii);
            strcat(messageAscii, " d");

            if ((ret = write(fd, messageAscii, strlen(messageAscii))) < 0)
            {
                perror("Falha ao enviar mensagem");
                return errno;
            }

            printf("\nPressione ENTER para ler a resposta\n");
            getchar();

            if ((ret = read(fd, receive, BUFFER_LENGTH)) < 0)
            {
                perror("Falha ao ler resposta");
                return errno;
            }

            printf("Mensagem Decifrada: ");
            printHexDump(receive, option2, 16);
            printf("\n\nPressione ENTER para continuar\n");
            getchar();

            break;

        case 3: //Hash

            clearScreen();
            printf("Digite a mensagem desejada: ");
            scanf("%[^\n]%*c", messageToSend);
            printf("\nMensagem enviada: %s\n", messageToPrint);
            strcat(messageToSend, " h");

            if ((ret = write(fd, messageToSend, strlen(messageToSend))) < 0)
            {
                perror("Falha ao enviar mensagem");
                return errno;
            }

            printf("\nPressione ENTER para ler a resposta\n");
            getchar();

            if ((ret = read(fd, receive, BUFFER_LENGTH)) < 0)
            {
                perror("Falha ao ler resposta");
                return errno;
            }

            printf("Resumo criptográfico: ");
            printHexDump(receive, option2, 20);
            printf("\n\nPressione ENTER para continuar\n");
            getchar();

            break;
        }

        clearScreen();
        printf("====================\n");
        printf("1.Continuar\n");
        printf("0.Sair\n");
        printf("====================\n");
        printf("Digite a opção desejada: ");
        scanf("%d", &option1);
        getchar();

    } while (option1 != 0);

    if ((ret = close(fd)) < 0)
    {
        perror("Erro ao fechar o arquivo");
        return errno;
    }

    return 0;
}

/* ================================================== */

void clearMessage(char message[])
{
    for (int i = 0; i < strlen(message); i++)
    {
        message[i] = '\0';
    }
}

/* ================================================== */

void clearScreen()
{
    printf("\033[H\033[J");
}

/* ================================================== */

void printHexDump(const void *message, int algorithm, int length)
{
    char ascii[50];
    int i;
    ascii[50] = '\0';

    for (i = 0; i < length; ++i)
    {
        printf("%02X", ((unsigned char *)message)[i]);
        if (((unsigned char *)message)[i] >= ' ' && ((unsigned char *)message)[i] <= '~')
        {
            ascii[i % 16] = ((unsigned char *)message)[i];
        }
        else
        {
            ascii[i % 16] = '\0';
        }
        if ((i + 1) % 8 == 0 || i + 1 == length)
        {
            if ((i + 1) % 16 == 0)
            {
                if (algorithm == 2)
                    printf("\n%s\n", ascii);
            }
            else if (i + 1 == length)
            {
                ascii[(i + 1) % 16] = '\0';
                if (algorithm == 2)
                    printf("\n%s\n", ascii);
            }
        }
    }
}

/* ================================================== */

void hexToAscii(char messageHexa[], char messageChar[])
{
    int i = 0, j = 0;
    int num;
    char temp[3];

    for (i = 0; i < strlen(messageHexa) + 1; i += 2)
    {
        sprintf(temp, "%c%c", messageHexa[i], messageHexa[i + 1]);
        num = (int)strtol(temp, NULL, 16);
        messageChar[j] = (char)num;
        j++;
    }
}
