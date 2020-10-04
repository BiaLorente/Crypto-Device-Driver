#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <stdio_ext.h>

#define BUFFER_LENGTH 256         ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH]; ///< The receive buffer from the LKM

void clearMessage(char[]);
void clearScreen();
void dumpHex(const void *, int);

int main()
{
    setlocale(LC_ALL, "Portuguese");

    int ret, fd;
    int option1, option2;
    char messageToSend[BUFFER_LENGTH+2];
    char messageToPrint[BUFFER_LENGTH];

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
	    strcpy(messageToPrint, messageToSend);
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

            printf("String enviada: %s\n", messageToPrint);
	    printf("Mensagem cifrada: ");
            dumpHex(receive, option2);
            printf("\n\nPressione ENTER para continuar\n");
            getchar();

            break;

        case 2: //Decifrar

            clearScreen();
	    printf("Digite a mensagem para ser decifrada: ");
	    scanf("%[^\n]%*c", messageToSend);
	    strcpy(messageToPrint, messageToSend);
	    strcat(messageToSend, " d");

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

            printf("Mensagem Enviada: %s\n", messageToPrint);
	    printf("Mensagem Decifrada: ");
	    dumpHex(receive, option2);
            printf("\n\nPressione ENTER para continuar\n");
            getchar();

            break;

        case 3: //Hash

	    clearScreen();
	    printf("Digite a mensagem para ser decifrada: ");
	    scanf("%[^\n]%*c", messageToSend);
	    strcpy(messageToPrint, messageToSend);
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

	    printf("Mensagem enviada: %s\n", messageToPrint);
            printf("Resumo critográfico: ");
            dumpHex(receive, option2);
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

void dumpHex(const void *message, int algorithm)
{
    char ascii[BUFFER_LENGTH];
    size_t i, j;
    ascii[BUFFER_LENGTH] = '\0';

    for (i = 0; i < strlen(message); ++i)
    {
        printf("%02X", ((unsigned char *)message)[i]);
        if (((unsigned char *)message)[i] >= ' ' && ((unsigned char *)message)[i] <= '~')
        {
            ascii[i % strlen(message)] = ((unsigned char *)message)[i];
        }
        else
        {
            ascii[i % strlen(message)] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == strlen(message))
        {
            printf(" ");
            if ((i + 1) % strlen(message) == 0)
            {
	        if(algorithm == 2)
                printf("\n%s\n", ascii);
            }
            else if (i + 1 == strlen(message))
            {
                ascii[(i + 1) % strlen(message)] = '\0';
                if ((i + 1) % strlen(message) <= 8)
                {
                    printf(" ");
                }
                for (j = (i + 1) % strlen(message); j < strlen(message); ++j)
                {
                    printf("   ");
                }

		if(algorithm == 2)
                printf("\n%s\n", ascii);
            }
        }
    }

}
