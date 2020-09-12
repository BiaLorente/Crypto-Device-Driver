/* 
 * Simple demo explaining usage of the Linux kernel CryptoAPI.
 * By Michal Ludvig <michal@logix.cz>
 *    http://www.logix.cz/michal/
 */

/*Includes Bibliotecas*/
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <asm/scatterlist.h>

#define PFX "cryptoapi-demo: "

MODULE_AUTHOR("Michal Ludvig <michal@logix.cz>"); //Autor
MODULE_DESCRIPTION("Simple CryptoAPI demo"); //Descrição
MODULE_LICENSE("GPL"); //Licença do modulo

/* ====== CryptoAPI ====== */

#define DATA_SIZE       16 //Tamanho maximo dos dados

#define FILL_SG(sg,ptr,len)     do { (sg)->page = virt_to_page(ptr); (sg)->offset = offset_in_page(ptr); (sg)->length = len; } while (0)

static void
hexdump(unsigned char *buf, unsigned int len)
{
        while (len--)
                printk("%02x", *buf++);

        printk("\n");
}

static void
cryptoapi_demo(void)
{
        /* config options */
        char *algo = "aes"; //Tipo do algoritmo
        int mode = CRYPTO_TFM_MODE_CBC;
        char key[16], iv[16]; //Tamanho maximo da chave e do iv -> 16bits

        /* local variables */
        struct crypto_tfm *tfm;
        struct scatterlist sg[8];
        int ret;
        char *input, *encrypted, *decrypted;
	
	//memset -> Preenche um bloco com um determinado valor, nesse caso 0
        memset(key, 0, sizeof(key)); //Key definida como 0
        memset(iv, 0, sizeof(iv)); //Iv definida como 0

        tfm = crypto_alloc_tfm (algo, mode); //Define o tipo do algoritmo que vai ser o programa e o modo

        if (tfm == NULL) {
		//printk -> Kernel print
		//Erro em alocar o tipo de criptografia
                printk("failed to load transform for %s %s\n", algo, mode == CRYPTO_TFM_MODE_CBC ? "CBC" : "");
                return;
        }

        ret = crypto_cipher_setkey(tfm, key, sizeof(key)); //Define a chave pra criptografia

        if (ret) {
                printk(KERN_ERR PFX "setkey() failed flags=%x\n", tfm->crt_flags); //Erro em definir a chave
                goto out;
        }

        input = kmalloc(GFP_KERNEL, DATA_SIZE); //kmalloc -> kernel malloc
	//Tentativa de alocar no kernel o tamanho dos dados
        if (!input) {
                printk(KERN_ERR PFX "kmalloc(input) failed\n"); //Erro na alocação
                goto out;
        }

        encrypted = kmalloc(GFP_KERNEL, DATA_SIZE); //Alocar para encriptar
        if (!encrypted) {
                printk(KERN_ERR PFX "kmalloc(encrypted) failed\n"); //Erro na criptografia
                kfree(input); //Libera o espaço alocado do kernel
                goto out;
        }

        decrypted = kmalloc(GFP_KERNEL, DATA_SIZE); //Alocar para descriptografar
        if (!decrypted) {
                printk(KERN_ERR PFX "kmalloc(decrypted) failed\n"); //Erro na descriptografia
                kfree(encrypted); //Libera o espaço alocado do kernel
                kfree(input); //Libera o espaço alocado do kernel
                goto out;
        }

        memset(input, 0, DATA_SIZE); //Define entrada como 0

        FILL_SG(&sg[0], input, DATA_SIZE);
        FILL_SG(&sg[1], encrypted, DATA_SIZE);
        FILL_SG(&sg[2], decrypted, DATA_SIZE);

        crypto_cipher_set_iv(tfm, iv, crypto_tfm_alg_ivsize (tfm));
        ret = crypto_cipher_encrypt(tfm, &sg[1], &sg[0], DATA_SIZE); //Define a cifra e criptografa o input
        if (ret) {
                printk(KERN_ERR PFX "encryption failed, flags=0x%x\n", tfm->crt_flags); //Erro na criptografia
                goto out_kfree;
        }

        crypto_cipher_set_iv(tfm, iv, crypto_tfm_alg_ivsize (tfm));
        ret = crypto_cipher_decrypt(tfm, &sg[2], &sg[1], DATA_SIZE); //Para a cifra e descriptografa o input
        if (ret) {
                printk(KERN_ERR PFX "decryption failed, flags=0x%x\n", tfm->crt_flags); //Erro na descriptografia
                goto out_kfree;
        }

        printk(KERN_ERR PFX "IN: "); hexdump(input, DATA_SIZE);
        printk(KERN_ERR PFX "EN: "); hexdump(encrypted, DATA_SIZE);
        printk(KERN_ERR PFX "DE: "); hexdump(decrypted, DATA_SIZE);

        if (memcmp(input, decrypted, DATA_SIZE) != 0)
                printk(KERN_ERR PFX "FAIL: input buffer != decrypted buffer\n");
        else
                printk(KERN_ERR PFX "PASS: encryption/decryption verified\n");

out_kfree:
        kfree(decrypted);
        kfree(encrypted);
        kfree(input);

out:
        crypto_free_tfm(tfm);
}

/* ====== Module init/exit ====== */

//Inicialização do modulo
static int __init
init_cryptoapi_demo(void)
{
        cryptoapi_demo();

        return 0;
}

//Finalização do modulo
static void __exit
exit_cryptoapi_demo(void)
{
}

module_init(init_cryptoapi_demo);
module_exit(exit_cryptoapi_demo);
