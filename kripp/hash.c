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

#define  DEVICE_NAME "cryptoTest"    
#define  CLASS_NAME  "crypTest"   
     
#define FILL_SG(sg,ptr,len)     do { (sg)->page = virt_to_page(ptr); (sg)->offset = offset_in_page(ptr); (sg)->length = len; } while (0)

//insmod cryptomodule.ko key=”0123456789ABCDEF” iv=”0123456789ABCDEF”
#define KEY_SIZE 16
#define IV_SIZE 16

MODULE_LICENSE("GPL");            
MODULE_AUTHOR("Pedroit");    
MODULE_DESCRIPTION("CryptoModule for SOB - Project 1");  
MODULE_SUPPORTED_DEVICE("crypto");
MODULE_VERSION("0.1"); 

/*========================================================================*/
//Variaveis
static int    majorNumber;                  
static char   message[256] = {0};           
static short  size_of_message;              
static int    numberOpens = 0;              
static struct class*  ebbcharClass  = NULL; 
static struct device* ebbcharDevice = NULL; 
//DEFINE_MUTEX -> Declara e inicializa o mutex, normalmente utilizado para mutex utilizado de forma global
static DEFINE_MUTEX(crypto_mutex);

char key[16];
char iv[16];

/*static char crypto_key[KEY_SIZE];
static char crypto_iv[IV_SIZE];*/
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

static void hexdump(unsigned char *buf, unsigned int len)
{
        while (len--)
	printfk("%02x", *buff++);
        printk("\n");
}

/* ================================================== */

static int __init crypto_init(void) {

mutex_init(&crypto_mutex);

majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "Crypto failed to register a major number\n");
      return majorNumber;
   }

// Register the device class
   ebbcharClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(ebbcharClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(ebbcharClass);          // Correct way to return an error on a pointer
   }
   printk(KERN_INFO "EBBChar: device class registered correctly\n");

   // Register the device driver
   ebbcharDevice = device_create(ebbcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(ebbcharDevice)){               // Clean up if there is an error
      class_destroy(ebbcharClass);          
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(ebbcharDevice);
   }

   printk(KERN_INFO "EBBChar: device class created correctly\n"); // Made it! device was initialized
   return 0;
}

}


static void __exit crypto_exit(void){
   mutex_destroy(&crypto_mutex);                           
   device_destroy(ebbcharClass, MKDEV(majorNumber, 0));     
   class_unregister(ebbcharClass);                          
   class_destroy(ebbcharClass);                             
   unregister_chrdev(majorNumber, DEVICE_NAME);             
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
   }
   else {
      printk(KERN_INFO "Crypto: Failed to send %d characters to the user\n", error_count);
      return -EFAULT;              
   }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){

   sprintf(message, "%s", buffer);   
   size_of_message = strlen(message);                // store the length of the stored message

    switch(message[0]){
      case 'c': // cifrar
		printk("Cifrar mensagem");
		encrypt(message, size_of_message);
	break;
	  case 'd': // decifrar	
		printk("Decifrar mensagem");
		decrypt(message, size_of_message);		
    	break;
      case 'h': // resumo criptográfico
		printk("Hash mensagem");
		hash(message, size_of_message);
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

   return 0;
}

/* ================================================== */

static int decrypt(char *message, int messageLength)
{
	return 0;
}

/* ================================================== */

static int hash(char *message, int messageLength)
{

struct scatterlist sg; // Hold you plaintext in a format that crypto.h can understand
struct hash_desc desc; // Config hash

char *plaintext = "plaintext goes here"; // Hold the plaintext
size_t len = strlen(plaintext); //Hold de size of our plaintext
u8 hashval[20]; // Hold the hash of our plaintext

sg_init_one(&sg,plaintext,len);
desc.tfm= crypto_alloc_hash("sha1",0,CRYPTO_ALG_ASYNC);

crypto_hash_init(&desc);
crypto_hash_update(&desc,&sg,len);
crypto_hash_final(&desc,hasval);

crypto_free_hash(desc.tfm);



	return 0;
}


module_init(crypto_init);
module_exit(crypto_exit);

