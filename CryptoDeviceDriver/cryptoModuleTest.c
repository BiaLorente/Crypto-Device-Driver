#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>

#define BUFFER_LENGTH 256           ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH]; ///< The receive buffer from the LKM

void clearMessage(char[]);
void clearScreen();

int main()
{
    setlocale(LC_ALL, "Portuguese");

    int ret, fd;
    int option1, option2;
    char messageToEncrypt[BUFFER_LENGTH];

    printf("Starting device test code example...\n");

    
    if ((fd = open("/dev/crypto", O_RDWR)) < 0)
    {
        perror("Failed to open the device...");
        return errno;
    }

    do
    {
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

        } while (option2 < 0 || option2 > 3);

        switch (option2)
        {
        case 0:
            return 0;
            break;

        case 1: //Cifrar
	    printf("oi");
	    getchar();
            clearScreen();
            clearMessage(messageToEncrypt);
            printf("Digite a mensagem para ser decifrada: ");
            scanf("%[^\n]%*c", messageToEncrypt);
            

            if ((ret = write(fd, messageToEncrypt, strlen(messageToEncrypt))) < 0)
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

            printf("Mensagem Cifrada: [%s]\n", receive);
	    printf("Pressione ENTER para continuar\n");
	    getchar();

            break;

        case 2: //Decifrar
            break;

        case 3: //Hash
            break;
        }

        clearScreen();
        printf("====================\n");
        printf("1.Continuar\n");
        printf("0.Sair\n");
        printf("====================\n");
        printf("Digite a opção desejada: ");
        scanf("%d", &option1);

    } while (option1 != 0);

    close(fd);

    return 0;

    return 0;
}

void clearMessage(char message[])
{
    for (int i = 0; i < strlen(message); i++)
    {
        message[i] = '\0';
    }
}

void clearScreen()
{
    printf("\033[H\033[J");
}
