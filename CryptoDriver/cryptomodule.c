#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/moduleparam.h>
#include <linux/stat.h>
#include <linux/crypto.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/vmalloc.h>
#include <crypto/hash.h>

#define  DEVICE_NAME "crypto"    
#define  CLASS_NAME  "cry" 
#define SHA1_SIZE 20  
     
#define FILL_SG(sg,ptr,len)     do { (sg)->page = virt_to_page(ptr); (sg)->offset = offset_in_page(ptr); (sg)->length = len; } while (0)

//insmod cryptomodule.ko key=”0123456789ABCDEF” iv=”0123456789ABCDEF”
#define KEY_SIZE 16
#define IV_SIZE 16

#define AES_KEY 256

MODULE_LICENSE("GPL");            
MODULE_AUTHOR("Pedroit");    
MODULE_DESCRIPTION("CryptoDeviceDriver");  
MODULE_SUPPORTED_DEVICE("crypto");
MODULE_VERSION("1.0"); 

/*========================================================================*/
//Variaveis
static int    majorNumber;                  
static char   message[258] = {0};           
static short  size_of_message;              
static int    numberOpens = 0;              
static struct class*  cryptoClass  = NULL; 
static struct device* cryptoDevice = NULL; 

static DEFINE_MUTEX(crypto_mutex);

char *key;
char *iv;

//static char *returnMsg;
//static int TAM_resposta;

static char crp_key_hex[33];
static char crp_iv_hex[33];

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

/* ================================================== */



/* ================================================== */

static int __init crypto_init(void) {

printk(KERN_INFO "Crypto Module: Initializing the Crypto Module LKM\n");

static int i;

    /*  Copiando conteudo para os vetores */
    for(i = 0; i < strlen(key) && i < 33 - 1; i++)
	    crp_key_hex[i] = key[i];

    if(i < 33 - 1) 
	    for(; i < 33 - 1; i++)
		    crp_key_hex[i] = '0';

    for(i = 0; i < strlen(iv) && i < 33 - 1; i++)
	    crp_iv_hex[i] = iv[i];

    if(i < 33 - 1) 
	    for(; i < 33 - 1; i++)
		    crp_iv_hex[i] = '0';

    crp_key_hex[33 - 1] = '\0';
    crp_iv_hex[33 - 1] = '\0';

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

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{

	sprintf(message, "%s", buffer);	   // appending received string with its length
	size_of_message = strlen(message); // store the length of the stored message
	printk(KERN_INFO "Crypto Module: Received %zu characters from the user\n", len);

	switch (message[size_of_message - 1])
	{

	case 'c':
		encrypt(message, size_of_message - 2);
		break;

	case 'd':
		decrypt(message, size_of_message - 2);
		break;

	case 'h':
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
    char *cryptograf = NULL;
    struct scatterlist sg_cryptograf;
    struct scatterlist sg_scratchpad;

    char *Eivdata = NULL;
    char *Ekey = NULL;

    int ivSize;
    int scratchpad_size;
    int cypherBlocks;

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

    ivSize = crypto_skcipher_ivsize(tfm);

    Ekey = vmalloc(KEY_SIZE);
    if (!Ekey) {
        pr_info("Could not allocate key\n");
        goto out;
    }


    strcpy(Ekey, crypto_key);

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

    strcpy(Eivdata, crypto_iv);

    /* Verificar se será necessário fazer padding */
    if (messageLength % IV_SIZE) {
        cypherBlocks = 1 + (messageLength / IV_SIZE);
        scratchpad_size = IV_SIZE * cypherBlocks;
    } else {
        cypherBlocks = messageLength / IV_SIZE;
        scratchpad_size = messageLength;
    }
    
    
    scratchpad = vmalloc(messageLength);
    if (!scratchpad) {
        pr_info("Could not allocate scratchpad\n");
        goto out;
    }
    

    /* Preencher o espaço alocado */
    for(i=0; i<messageLength;   i++) scratchpad[i] = message[i];

    /* Realizar padding se necessário */
    for(; i<scratchpad_size; i++) {
	scratchpad[i] = 0;
	}
    
    /* Requisitar uma área de memória para alocar o resultado da criptografia */
    cryptograf = vmalloc(scratchpad_size);
    if (!cryptograf) {
        pr_info("Could not allocate cryptograf\n");
        goto out;
    }

    
    /* scatterlists */
    sg_init_one(&sg_scratchpad, scratchpad, scratchpad_size);
    sg_init_one(&sg_cryptograf, cryptograf, scratchpad_size);
     

    skcipher_request_set_crypt(req, &sg_scratchpad, &sg_cryptograf, scratchpad_size, Eivdata);

     //reference to the skcipher_request handle that holds all information needed to perform the cipher operation
     ret = crypto_skcipher_encrypt(req);
    
     if (ret) {
        printk(KERN_INFO "Encryption failed...\n");
        goto out;
    }

	
    //Exibir resultado para debug 
    cryptoResult = sg_virt(&sg_cryptograf);

    strcpy(message, cryptoResult);
    printk("========================================");
    print_hex_dump(KERN_DEBUG, "Result Data Encrypt: ", DUMP_PREFIX_NONE, 16, 1, cryptoResult, 16, true);
    printk("========================================");


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
    if (cryptograf)
        vfree(cryptograf);
    return ret;
}


/* ================================================== */

static int decrypt(char *message, int messageLength)
{

    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;

    char *scratchpad = NULL;
    char *decryptoResult = NULL;
    char *decryptograf = NULL;
    struct scatterlist sg_cryptograf;
    struct scatterlist sg_scratchpad;

    char *Eivdata = NULL;
    char *Ekey = NULL;

    int ivSize;
    int scratchpad_size;
    int cypherBlocks;

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

    ivSize = crypto_skcipher_ivsize(tfm);

    Ekey = vmalloc(KEY_SIZE);
    if (!Ekey) {
        pr_info("Could not allocate key\n");
        goto out;
    }


    strcpy(Ekey, crypto_key);


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


    strcpy(Eivdata, crypto_iv);

    /* Verificar se será necessário fazer padding */
    if (messageLength % IV_SIZE) {
        cypherBlocks = 1 + (messageLength / IV_SIZE);
        scratchpad_size = IV_SIZE * cypherBlocks;
    } else {
        cypherBlocks = messageLength / IV_SIZE;
        scratchpad_size = messageLength;
    }
    
    
    scratchpad = vmalloc(messageLength);
    if (!scratchpad) {
        pr_info("Could not allocate scratchpad\n");
        goto out;
    }
    

    /* Preencher o espaço alocado */
    for(i=0; i<messageLength;   i++) scratchpad[i] = message[i];


    /* Realizar padding se necessário */
    for(; i<scratchpad_size; i++) {
	scratchpad[i] = 0;
	}
    
    /* Requisitar uma área de memória para alocar o resultado da criptografia */
    decryptograf = vmalloc(scratchpad_size);
    if (!decryptograf) {
        pr_info("Could not allocate decryptograf\n");
        goto out;
    }

    
    /* scatterlists */
    sg_init_one(&sg_scratchpad, scratchpad, scratchpad_size);
    sg_init_one(&sg_cryptograf, decryptograf, scratchpad_size);

    skcipher_request_set_crypt(req, &sg_scratchpad, &sg_cryptograf, scratchpad_size, Eivdata);

    ret = crypto_skcipher_decrypt(req);

    if(ret) {
      
      pr_info("Erro ao fazer o Decryption\n");
      goto out;
    }
    
	//Exibir resultado para debug 
    decryptoResult = sg_virt(&sg_cryptograf);

    printk("====================");
    print_hex_dump(KERN_DEBUG, "Result Data Decrypt: ", DUMP_PREFIX_NONE, 16, 1, decryptoResult, 16, true);
    printk("====================");


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
    if (decryptograf)
        vfree(decryptograf);
    return ret;
}

/* ================================================== */

static int hash(char *message, int messageLength)
{
	struct shash_desc *shash;
	struct crypto_shash *req;
	char *result = NULL;
	int ret;

	req = crypto_alloc_shash("sha1", 0, 0);
	shash = vmalloc(sizeof(struct shash_desc));
	if (!shash)
		goto out;

	shash->tfm = req;
	shash->flags = 0x0;

	result = vmalloc(SHA1_SIZE * 2);
	if (!result)
		goto out;

	ret = crypto_shash_digest(shash, message, messageLength, result);
	strcpy(message, result);

	printk("====================");
	print_hex_dump(KERN_DEBUG, "Result Data Hash: ", DUMP_PREFIX_NONE, 16, 1, result, 16, true);
	printk("====================");

	/* ==================== */

	out:
	if (req)
		crypto_free_shash(req);
	if (shash)
		vfree(shash);
	if (result)
		vfree(result);

	return 0;
}


module_init(crypto_init);
module_exit(crypto_exit);

