#include <linux/init.h>           
#include <linux/module.h>         
#include <linux/device.h>        
#include <linux/kernel.h>         
#include <linux/fs.h>             
#include <linux/uaccess.h>          
#include <linux/mutex.h>
#include <linux/moduleparam.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <linux/err.h>
#include <linux/vmalloc.h>

#define  DEVICE_NAME "cryptoModule"    
#define  CLASS_NAME  "cryptoSOB"   
     
#define FILL_SG(sg,ptr,len)     do { (sg)->page = virt_to_page(ptr); (sg)->offset = offset_in_page(ptr); (sg)->length = len; } while (0)

//insmod cryptomodule.ko key=”0123456789ABCDEF” iv=”0123456789ABCDEF”
#define KEY_SIZE 16
#define IV_SIZE 16

#define AES_KEY 256

MODULE_LICENSE("GPL");            
MODULE_AUTHOR("Pedroit");    
MODULE_DESCRIPTION("CryptoModule for SOB - Project 1");  
MODULE_SUPPORTED_DEVICE("crypto");
MODULE_VERSION("1.0"); 

/*========================================================================*/
//Variaveis
static int    majorNumber;                  
static char   message[256] = {0};           
static short  size_of_message;              
static int    numberOpens = 0;              
static struct class*  cryptoClass  = NULL; 
static struct device* cryptoDevice = NULL; 
//DEFINE_MUTEX -> Declara e inicializa o mutex, normalmente utilizado para mutex utilizado de forma global
static DEFINE_MUTEX(crypto_mutex);

char *key;
char *iv;

static char *returnMsg;
static int TAM_resposta;

static char crypto_key[KEY_SIZE];
static char crypto_iv[IV_SIZE];
//SHA1

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Chave para o algoritmo AES-CBC");
module_param(iv, charp, 0000);
MODULE_PARM_DESC(iv, "Vetor de inicialização para o algoritmo AES-CBC");

/*=======================================================================*/
// The prototype functions for the character driver -- must come before the struct definition
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};

/* ================================================== */

static int encrypt(char *message, int messageLength);
static int decrypt(char *message, int messageLength);
static int hash(char *message, int messageLength);
char c2h_conv(char c);

/* ================================================== */

char c2h_conv(char c) {
    if (c < (char)10) return c + '0';
    return c + 'A' - (char)10;
}

/* ================================================== */

static int __init crypto_init(void) {

printk(KERN_INFO "Crypto Module: Initializing the Crypto Module LKM\n");

mutex_init(&crypto_mutex);

majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "Crypto failed to register a major number\n");
      return majorNumber;
   }

printk(KERN_INFO "Crypto Module: registered correctly with major number %d\n", majorNumber);

// Register the device class
   cryptoClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(cryptoClass)){                
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(cryptoClass);          
   }
   printk(KERN_INFO "Crypto Module: device class registered correctly\n");

   // Register the device driver
   cryptoDevice = device_create(cryptoClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(cryptoDevice)){              
      class_destroy(cryptoClass);          
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(cryptoDevice);
   }

   printk(KERN_INFO "Crypto Module: device class created correctly\n"); 
   return 0;
}


/* ================================================== */

static void __exit crypto_exit(void){
   mutex_destroy(&crypto_mutex);                           
   device_destroy(cryptoClass, MKDEV(majorNumber, 0));     
   class_unregister(cryptoClass);                          
   class_destroy(cryptoClass);                             
   unregister_chrdev(majorNumber, DEVICE_NAME);    
   printk(KERN_INFO "Crypto Module: Goodbye from the LKM!\n");         
}

static int dev_open(struct inode *inodep, struct file *filep){
   mutex_lock(&crypto_mutex);
   numberOpens++;
   return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   // copy_to_user has the format ( * to, *from, size) and returns 0 on success
   error_count = copy_to_user(buffer, message, size_of_message);

   if (error_count==0){            
      return (size_of_message=0);

   } else {
      printk(KERN_INFO "Crypto: Failed to send %d characters to the user\n", error_count);
      return -EFAULT;              
   }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){  
   size_of_message = strlen(message);                // store the length of the stored message
printk(KERN_INFO "Crypto Module: Received %zu characters from the user\n", len);

    switch(message[size_of_message - 1]){
      case 'c': // cifrar
		printk("Cifrar mensagem");
		encrypt(message, size_of_message - 2);
	break;

      case 'd': // decifrar	
		printk("Decifrar mensagem");
		decrypt(message, size_of_message - 2);		
    	break;

      case 'h': // resumo criptográfico
		printk("Hash mensagem");
		hash(message, size_of_message - 2);
    	break;
   }


   return len;
}

static int dev_release(struct inode *inodep, struct file *filep){
   mutex_unlock(&crypto_mutex);
   printk(KERN_INFO "Crypto: Device successfully closed\n");
   return 0;
}

/* ================================================== */

static int encrypt(char *message, int messageLength)
{

   /*Componente de cada struct https://coggle.it/diagram/W3pwQodcxh6nB7Wy/t/struct-crypto_tfm-u32-9-include-linux-crypto-h-537 */
   struct crypto_skcipher *tfm = NULL;
   struct skcipher_request *req = NULL;

    char *scratchpad = NULL;
    char *cryptoResult = NULL;
    char *criptograf = NULL;
    struct scatterlist sg_criptograf;
    struct scatterlist sg_scratchpad;

    char *Eivdata = NULL;
    char *Ekey = NULL;

    int expected_iv_size;
    int scratchpad_size;
    int n_cipher_blocks;

    int ret = -EFAULT;

    int i;

    tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0); //cbc-aes

    if (IS_ERR(tfm)) {
        printk(KERN_INFO "Could not allocate skcipher (%ld)\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
        goto out;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        printk(KERN_INFO "Could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    expected_iv_size = crypto_skcipher_ivsize(tfm);

    Ekey = vmalloc(KEY_SIZE);
    if (!Ekey) {
        pr_info("Could not allocate key\n");
        goto out;
    }


    for(i=0; i<KEY_SIZE; i++) {

	Ekey[i] = crypto_key[i]; 

    }

    if (crypto_skcipher_setkey(tfm, Ekey, KEY_SIZE)) {
        pr_info("Key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    Eivdata = vmalloc(IV_SIZE);
    if (!Eivdata) {
        pr_info("Could not allocate ivdata\n");
        goto out;
    }

    /* Preencher o espaço alocado */
    for(i=0; i<IV_SIZE; i++) {
	  Eivdata[i] = crypto_iv[i];
	}

    /* Verificar se será necessário fazer padding */
    if (messageLength % IV_SIZE) {
        n_cipher_blocks = 1 + (messageLength / IV_SIZE);
        scratchpad_size = IV_SIZE * n_cipher_blocks;
    } else {
        n_cipher_blocks = messageLength / IV_SIZE;
        scratchpad_size = messageLength;
    }
    
    
    scratchpad = vmalloc(messageLength);
    if (!scratchpad) {
        pr_info("Could not allocate scratchpad\n");
        goto out;
    }
    

    for(i=0; i < messageLength;   i++) {
	scratchpad[i] = message[i];
	}

    /* Realizar padding se necessário */
    for(; i<scratchpad_size; i++) {
	scratchpad[i] = 0;
	}
    
    /* Requisitar uma área de memória para alocar o resultado da criptografia */
    criptograf = vmalloc(scratchpad_size);
    if (!criptograf) {
        pr_info("Could not allocate criptograf\n");
        goto out;
    }

    
    /* scatterlists */
    sg_init_one(&sg_scratchpad, scratchpad, scratchpad_size);
    sg_init_one(&sg_criptograf, criptograf, scratchpad_size);
     
     
     skcipher_request_set_crypt(req, &sg_scratchpad, &sg_criptograf, scratchpad_size, Eivdata);


     //reference to the skcipher_request handle that holds all information needed to perform the cipher operation
     ret = crypto_skcipher_encrypt(req);
    
     if (ret) {
        printk(KERN_INFO "Encryption failed...\n");
        goto out;
    }

	
    //Exibir resultado para debug 
    cryptoResult = sg_virt(&sg_criptograf);

    /*Armazenar resposta para devolver ao programa  */
    for(i=0;i<scratchpad_size;i++){
	    returnMsg[2*i] = c2h_conv((unsigned char)cryptoResult[i] / 16);
	    returnMsg[2*i + 1] = c2h_conv((unsigned char)cryptoResult[i] % 16);
	}
    returnMsg[2*i] = 0;
    
    /* Armazenar tamanho da resposta do programa */
    TAM_resposta = 2*scratchpad_size + 1; 


    out:
    if (tfm)
        crypto_free_skcipher(tfm);
    if (req)
        skcipher_request_free(req);
    if (Ekey)
    	vfree(Ekey);
    if (Eivdata)
        vfree(Eivdata);
    if (scratchpad)
        vfree(scratchpad);
    if (criptograf)
        vfree(criptograf);
    return ret;
}


/* ================================================== */

static int decrypt(char *message, int messageLength)
{
	return 0;
}

/* ================================================== */

static int hash(char *message, int messageLength)
{
	return 0;
}


module_init(crypto_init);
module_exit(crypto_exit);

