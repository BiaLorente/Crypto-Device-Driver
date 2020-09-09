#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_LENGTH 256           ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH]; ///< The receive buffer from the LKM

int main()
{
    int ret, fd;
    char messageToEncrypt[BUFFER_LENGTH];

    printf("Starting device test code example...\n");

    /* Abre device */
    if ((fd = open("/dev/crypto", O_RDWR)) < 0)
    {
        perror("Failed to open the device...");
        return errno;
    }

    /* Frase enviada ao módulo */
    printf("Type in a short string to send to the kernel module:\n");
    scanf("%[^\n]%*c", messageToEncrypt); // Read in a string (with spaces)
    /* Manda mensagem para o device */
    printf("Writing message to the device [%s].\n", messageToEncrypt);
    if((ret = write(fd, messageToEncrypt, strlen(messageToEncrypt))) < 0){
        perror("Failed to write the message to the device.");
        return errno;
    } 

    printf("Press ENTER to read back from the device...\n");
    getchar();

    /* Lê resposta do device*/
    printf("Reading from the device...\n");
    if((ret = read(fd, receive, BUFFER_LENGTH)) < 0){
        perror("Failed to read the message from the device.");
        return errno;
    }

    printf("The received message is: [%s]\n", receive);
    printf("End of the program\n");

    close(fd);

    return 0;
}