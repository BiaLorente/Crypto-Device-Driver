/*
 *  Arquivo de teste para o módulo de kernel
 *  cryptoModuleTest.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>

#define MAX_SIZE_MSG 150

void clearMessage(char[]);
void clearScreen();

int main(int argc, char *argv[])
{
    
    setlocale(LC_ALL, "Portuguese");

    int choice1, choice2;
    char messageArq[MAX_SIZE_MSG];
    char messageToEncrypt[MAX_SIZE_MSG];
    char messageDecrypted[MAX_SIZE_MSG];
    char messageHex[MAX_SIZE_MSG];

    /* Abrir arquivo */
    //fopen() / open()
    
    do
    {
        /* Pedir ao usuário opção desejada */
        do
        {
            clearScreen();
            printf("====================\n");
            printf("1 - Cifrar frase (c)\n");
            printf("2 - Decifrar frase (d)\n");
            printf("3 - Calcular resumo criptográfico (h)\n");
            printf("0 - Sair\n");
            printf("====================\n");
            printf("Digite a opção desejada: ");
            scanf("%d", &choice1);
        } while (choice1 < 0 || choice1 > 3);

        clearScreen();

        switch (choice1)
        {
        case 0:
            return 0;

        case 1:
            printf("===== CIFRAR ===== \n");
            clearMessage(messageToEncrypt); /* Limpar mensagem para não haver conflito */
            printf("Digite a mensagem a ser decifrada: ");
            /* Mandar 'c' para o módulo saber a ação */
            /* Ler do arquivo para obter resposta */
            /* Exibir resposta */
            break;

        case 2:
            printf("===== DECRIFRAR ===== \n");
            clearMessage(messageDecrypted); /* Limpar mensagem para não haver conflito */
            /* Mandar 'd' para o módulo saber a ação */
            /* Ler do arquivo para obter resposta */
            /* Exibir resposta */
            break;

        case 3:
            printf("===== RESUMO CRIPTOGRÁFICO ===== \n");
            clearMessage(messageHex); /* Limpar mensagem para não haver conflito */
            /* Mandar 'h' para o módulo saber a ação */
            /* Ler do arquivo para obter resposta */
            /* Converter string para hexa */
            /* Exibir resposta */
            break;
        }

        printf("\n====================\n");
        fflush(stdin);
        printf("1 - Continuar\n");
        printf("0 - Sair");
        printf("\n====================\n");
        printf("Digite a opção desejada: ");
        scanf("%d", &choice2);
    } while (choice2 != 0);

    clearScreen();

    /* Fechar arquivo */
    //fclose() / close()

    return 0;

}

/* Clear string content */
void clearMessage(char message[])
{
    for (int i = 0; i < strlen(message); i++)
    {
        message[i] = '\0';
    }
}

/* Convert string to hexadecimal */
void stringToHex()
{
}

/* Clear Terminal */
void clearScreen()
{
    printf("\033[H\033[J");
}

/* ==================================================================================================== */

/*
    #include <errno.h>
    #include <fcntl.h>
    FILE *arqcrypto;
    int iFileDescriptor;
    ssize_t iQtdeWrite;
    char msg[] = "teste";
    
    if ((arqcrypto = fopen("/dev/crypto/arqcrypto.txt", "w")) == NULL)
    {
        printf("Impossível abrir arquivo");
        exit(0);
    }

    fwrite(&msg, sizeof(msg), 1, arqcrypto);

    fclose(arqcrypto);
    */

/* ================================================ */

/*
    iFileDescriptor = open("/dev/crypto/arqcrypto.txt", O_RDWR);

    if(iFileDescriptor < 0){
        printf("Impossível abrir o arquivo\n");
        return errno;
    }
    
    iQtdeWrite = write (iFileDescriptor, &msg, strlen(msg));
    if(iQtdeWrite < strlen(msg)){
        printf("Erro ao escrever\n");
        return errno;
    }

    close(iFileDescriptor);
*/