/**
 * @file   cryptomodule.c
 * @author Bia Lorente
 * @date   ---------
 * @version 0.1
 * @brief   An introductory character driver to support the second article of my series on
 * Linux loadable kernel module (LKM) development. This module maps to /dev/crypto and
 * comes with a helper C program that can be run in Linux user space to communicate with
 * this the LKM.
 */
 
#include <linux/init.h>    
#include <linux/module.h>  
#include <linux/device.h>  
#include <linux/kernel.h>  
#include <linux/fs.h>      
#include <linux/uaccess.h> 
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/err.h>
#include <linux/mutex.h>	         /// Required for the mutex functionality
#define  DEVICE_NAME "crypto"    ///< The device will appear at /dev/crypto using this value
#define  CLASS_NAME  "cry"        ///< The device class -- this is a character device driver

/* ====== CryptoAPI ====== */
#define DATA_SIZE       16

#define FILL_SG(sg,ptr,len)     do { (sg)->page = virt_to_page(ptr); (sg)->offset = offset_in_page(ptr); (sg)->length = len; } while (0)


MODULE_LICENSE("GPL");            ///< The license type -- this affects available functionality
MODULE_AUTHOR("----");    ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple Linux crypto driver");  ///< The description -- see modinfo
MODULE_VERSION("1.0");            ///< A version number to inform users

static DEFINE_MUTEX(crypto_mutex);  /// A macro that is used to declare a new mutex that is visible in this file
                                     /// results in a semaphore variable crypto_mutex with value 1 (unlocked)
                                     /// DEFINE_MUTEX_LOCKED() results in a variable with value 0 (locked)

static int majorNumber;                    /* device number -> determinado automaticamente */
static char   message[256] = {0};           ///< Memory for the string that is passed from userspace
static short  size_of_message;              ///< Used to remember the size of the string stored
static int    numberOpens = 0;              ///< Counts the number of times the device is opened
static struct class*  cryptoClass  = NULL; ///< The device-driver class struct pointer
static struct device* cryptoDevice = NULL; ///< The device-driver device struct pointer

/*================Crypto things==================*/
struct tcrypt_result 
{
    struct completion completion;
    int err;
};

/* tie all data structures together */
struct skcipher_def 
{
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
}; 

//insmod cryptomodule.ko key=”0123456789ABCDEF” iv=”0123456789ABCDEF”

char *key;
char *iv;

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Chave para o algoritmo AES-CBC");
module_param(iv, charp, 0000);
MODULE_PARM_DESC(iv, "Vetor de inicialização para o algoritmo AES-CBC");



// The prototype functions
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

/*================Crypto things==================*/
static int encrypt(char *message, int messageLength);
static int decrypt(char *message, int messageLength);
static int hash(char *message, int messageLength);


static int __init crypto_init(void)
{
	printk(KERN_INFO "Crypto: Initializing the Crypto LKM\n");
   
      	mutex_init(&crypto_mutex);       /// Initialize the mutex lock dynamically at runtime


	majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
	if (majorNumber<0)
	{
      	printk(KERN_ALERT "Crypto failed to register a major number\n");
      	return majorNumber;
   	}
   	printk(KERN_INFO "Crypto: registered correctly with major number %d\n", majorNumber);

   	// Register the device class
   	cryptoClass = class_create(THIS_MODULE, CLASS_NAME);
   	if (IS_ERR(cryptoClass))
   	{                
   	// Check for error and clean up if there is
      	unregister_chrdev(majorNumber, DEVICE_NAME);
      	printk(KERN_ALERT "Failed to register device class\n");
      	return PTR_ERR(cryptoClass);          // Correct way to return an error on a pointer
	}
   	printk(KERN_INFO "Crypto: device class registered correctly\n");

   	// Register the device driver
   	cryptoDevice = device_create(cryptoClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   	if (IS_ERR(cryptoDevice))
   	{               
   	// Clean up if there is an error
      	class_destroy(cryptoClass);           // Repeated code but the alternative is goto statements
      	unregister_chrdev(majorNumber, DEVICE_NAME);
      	printk(KERN_ALERT "Failed to create the device\n");
      	return PTR_ERR(cryptoDevice);
   	}
   	printk(KERN_INFO "Crypto: device class created correctly\n"); // Made it! device was initialized
   	return 0;
}


static void __exit crypto_exit(void)
{
   mutex_destroy(&crypto_mutex);        /// destroy the dynamically-allocated mutex
   device_destroy(cryptoClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(cryptoClass);                          // unregister the device class
   class_destroy(cryptoClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
   printk(KERN_INFO "Crypto: Goodbye from the LKM!\n");
}


static int dev_open(struct inode *inodep, struct file *filep)
{
   	if(!mutex_trylock(&crypto_mutex))
   	{    /// Try to acquire the mutex (i.e., put the lock on/down)
                                          /// returns 1 if successful and 0 if there is contention
      	printk(KERN_ALERT "Crypto: Device in use by another process");
      	return -EBUSY;
	}
   	numberOpens++;
   	printk(KERN_INFO "Crypto: Device has been opened %d time(s)\n", numberOpens);
   	return 0;
}


static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   // copy_to_user has the format ( * to, *from, size) and returns 0 on success
   error_count = copy_to_user(buffer, message, size_of_message);

   if (error_count==0){            // if true then have success
      printk(KERN_INFO "Crypto: Sent %d characters to the user\n", size_of_message);
      return (size_of_message=0);  // clear the position to the start and return 0
   }
   else {
      printk(KERN_INFO "Crypto: Failed to send %d characters to the user\n", error_count);
      return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
   }
}

/** @brief This function is called whenever the device is being written to from user space i.e.
 *  data is sent to the device from the user. The data is copied to the message[] array in this
 *  LKM using the sprintf() function along with the length of the string.
 *  @param filep A pointer to a file object
 *  @param buffer The buffer to that contains the string to write to the device
 *  @param len The length of the array of data that is being passed in the const char buffer
 *  @param offset The offset if required
 */
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
   sprintf(message, "%s(%zu letters)", buffer, len);   // appending received string with its length
   size_of_message = strlen(message);                 // store the length of the stored message
   printk(KERN_INFO "Crypto: Received %zu characters from the user\n", len);
   return len;
}

/** @brief The device release function that is called whenever the device is closed/released by
 *  the userspace program
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_release(struct inode *inodep, struct file *filep){
   mutex_unlock(&crypto_mutex);          /// Releases the mutex (i.e., the lock goes up)
   printk(KERN_INFO "Crypto: Device successfully closed\n");
   return 0;
}

static int encrypt(char *message, int messageLength)
{
    int err;

    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct scatterlist sg;

    char plaintext[16] = {0};
    char ciphertext[16] = {0};
    /* We're going to use a zerod 128 bits key */
    char key[16] = {0};

    /* Initialization Vector */
    char *iv;
    size_t ivsize;

    pr_dbg("initializing module\n");

    /* Check the existence of the cipher in the kernel (it might be a
     * module and it isn't loaded. */
    if (!crypto_has_skcipher("salsa20", 0, 0)) {
        pr_err("skcipher not found\n");
        return -EINVAL;
    }

    /* Allocate synchronous cipher handler.
     *
     * For generic implementation you can provide either the generic name
     * "salsa20" or the driver (specific) name "salsa20-generic", since
     * the generic has higher priority compared to the x86_64 instruction
     * implementation "salsa20-asm".
     *
     * Also, cypher type will be left 0 since there isn't any other type
     * other than the default one for this cypher and the mask also will
     * be 0 since I don't want to use the asynchronous interface variant.
     */
    tfm = crypto_alloc_skcipher("salsa20", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("impossible to allocate skcipher\n");
        return PTR_ERR(tfm);
    }

    /* Default function to set the key for the symetric key cipher */
    err = crypto_skcipher_setkey(tfm, key, sizeof(key));
    if (err) {
        pr_err("fail setting key for transformation: %d\n", err);
        goto error0;
    }
    print_hex_dump(KERN_DEBUG, "key: ", DUMP_PREFIX_NONE, 16, 1, key, 16,
               false);

    /* Each crypto cipher has its own Initialization Vector (IV) size,
     * because of that I first request the correct size for salsa20 IV and
     * then set it. Considering this is just an example I'll use as IV the
     * content of a random memory space which I just allocated. */
    ivsize = crypto_skcipher_ivsize(tfm);
    iv = kmalloc(ivsize, GFP_KERNEL);
    if (!iv) {
        pr_err("could not allocate iv vector\n");
        err = -ENOMEM;
        goto error0;
    }
    print_hex_dump(KERN_DEBUG, "iv: ", DUMP_PREFIX_NONE, 16, 1, iv,
               ivsize, false);

    /* Requests are objects that hold all information about a crypto
     * operation, from the tfm itself to the buffers and IV that will be
     * used in the enc/decryption operations. But it also holds
     * information about asynchronous calls to the crypto engine. If we
     * have chosen async calls instead of sync ones, we should also set
     * the callback function and some other flags in the request object in
     * order to be able to receive the output date from each operation
     * finished. */
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        pr_err("impossible to allocate skcipher request\n");
        err = -ENOMEM;
        goto error0;
    }

    /* The word to be encrypted */
    /* TODO: explain scatter/gather lists, that has relation to DMA */
    memcpy(plaintext, "aloha", 6);
    sg_init_one(&sg, plaintext, 16);
    skcipher_request_set_crypt(req, &sg, &sg, 16, iv);

    print_hex_dump(KERN_DEBUG, "orig text: ", DUMP_PREFIX_NONE, 16, 1,
               plaintext, 16, true);

    /* Encrypt operation against "plaintext" content */
    err = crypto_skcipher_encrypt(req);
    if (err) {
        pr_err("could not encrypt data\n");
        goto error1;
    }

    sg_copy_to_buffer(&sg, 1, ciphertext, 16);
    print_hex_dump(KERN_DEBUG, "encr text: ", DUMP_PREFIX_NONE, 16, 1,
               ciphertext, 16, true);

    /* Time to decrypt */
    memset(plaintext, 0, 16);
    sg_init_one(&sg, ciphertext, 16);

    /* Decrypt operation against the new buffer (scatterlist that holds
     * the ciphered text). */
    err = crypto_skcipher_decrypt(req);
    if (err) {
        pr_err("could not decrypt data\n");
        goto error1;
    }

    sg_copy_to_buffer(&sg, 1, plaintext, 16);
    print_hex_dump(KERN_DEBUG, "decr text: ", DUMP_PREFIX_NONE, 16, 1,
               plaintext, 16, true);
error1:
    skcipher_request_free(req);
error0:
    crypto_free_skcipher(tfm);
    return err;
}

static void __exit crypto_sync_exit(void)
{
    PR_DEBUG("exiting module\n");
}
	


return 0;
}

module_init(crypto_init);
module_exit(crypto_exit);
