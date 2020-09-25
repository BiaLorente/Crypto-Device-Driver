/**
 * @file   cryptomodule.c
 * @author BiaLorente
 * @date   ---------
 * @version 1.0
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

#include <linux/scatterlist.h>
#include <linux/err.h>
#include <linux/mutex.h>	         /// Required for the mutex functionality
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/crypto.h>
#include <linux/random.h>
#include <linux/vmalloc.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>

#define  DEVICE_NAME "crypto"    ///< The device will appear at /dev/crypto using this value
#define  CLASS_NAME  "cry"        ///< The device class -- this is a character device driver

/* ====== CryptoAPI ====== */
#define DATA_SIZE       16

#define FILL_SG(sg,ptr,len)     do { (sg)->page = virt_to_page(ptr); (sg)->offset = offset_in_page(ptr); (sg)->length = len; } while (0)


MODULE_LICENSE("GPL");            ///< The license type -- this affects available functionality
MODULE_AUTHOR("BiaLorente");    ///< The author -- visible when you use modinfo
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
static DEFINE_MUTEX(crypto_mutex);	


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


//================================================

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
   sprintf(message, "%s", buffer); // appending received string with its length
	size_of_message = strlen(message);                // store the length of the stored message
	printk(KERN_INFO "Crypto Module: Received %zu characters from the user\n", len);

	switch(message[size_of_message - 1]){

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


static int dev_release(struct inode *inodep, struct file *filep)
{
   mutex_unlock(&crypto_mutex);          /// Releases the mutex (i.e., the lock goes up)
   printk(KERN_INFO "Crypto: Device successfully closed\n");
   return 0;
}

static int encrypt(char *message, int messageLength)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
   	struct skcipher_request *req = NULL;
	int rc = 0;

	int ret = -EFAULT;
	
	char *key_encrypt = NULL;
	char *iv_encrypt = NULL;
	char *scratchpad = NULL;
	char *result = NULL;

	int i;

	/* ==================== */

	/* Allocate a cipher handle for an skcipher */
	skcipher = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(skcipher)) {
		pr_info("could not allocate skcipher handle\n");
		return PTR_ERR(skcipher);
	}

	/* Allocate the request data structure that must be used with the skcipher encrypt and decrypt API calls */
	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		pr_info("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}
	
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, test_skcipher_cb, &sk.result);

	/* ==================== */

	/* Set key */
	key_encrypt = vmalloc(16);

	for(i = 0; i < 16; i++){
		key_encrypt[i] = key[i];
	}

	if (crypto_skcipher_setkey(skcipher, key_encrypt, 16)) {
   	     pr_err("fail setting key");
   	     goto out;
	}
	print_hex_dump(KERN_DEBUG, "Key_encrypt: ", DUMP_PREFIX_NONE, 16, 1, key_encrypt, 16, true);

	/* ==================== */

	iv_encrypt = vmalloc(16);

	if (!iv_encrypt) {
		pr_err("could not allocate iv vector\n");
		ret = -ENOMEM;
		goto out;
	}

	/* Preencher espaço alocado para iv */
	for(i = 0; i < 16; i++){
		iv_encrypt[i] = iv[i];
	}
		
	print_hex_dump(KERN_DEBUG, "IV Encrypt: ", DUMP_PREFIX_NONE, 16, 1, iv_encrypt, 16, true);

	/* ==================== */

	/* Set message */
	scratchpad = vmalloc(messageLength);
	if (!scratchpad) {
		pr_info("Could not allocate scratchpad\n");
		goto out;
	}
	
	/* Preencher espaço message */
	memcpy(scratchpad, message, messageLength);
	print_hex_dump(KERN_DEBUG, "Message: ", DUMP_PREFIX_NONE, 16, 1, scratchpad, 16, true);
	
	/* ==================== */

	/* Setando struct */
	sk.tfm = skcipher;
    	sk.req = req;


	/* Cifrar / Encrypt */
	sg_init_one(&sk.sg, scratchpad, 16);
	skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, iv_encrypt);
    	init_completion(&sk.result.completion);

	rc = crypto_skcipher_encrypt(req);
	
	if(rc){
		pr_info("skcipher encrypt returned with %d result %d\n", rc, sk.result.err);
		goto out;
	}

    	init_completion(&sk.result.completion);

	result = sg_virt(&sk.sg);
	print_hex_dump(KERN_DEBUG, "Result Data: ", DUMP_PREFIX_NONE, 16, 1, result, 16, true);
	
	/* ==================== */

	/* Out */
	out:
		if (skcipher) crypto_free_skcipher(skcipher);

		if (req) skcipher_request_free(req);

		if (key_encrypt) vfree(key_encrypt);

		if (iv_encrypt) vfree(iv_encrypt);

		if (scratchpad) vfree(scratchpad);

	return 0;
}

/* Callback function */
static void test_skcipher_cb(struct crypto_async_request *req, int error)
{
	struct tcrypt_result *result = req->data;

	if (error == -EINPROGRESS)
        	return;
	result->err = error;
	complete(&result->completion);
	//pr_info("Encryption finished successfully\n");
}
static void __exit crypto_sync_exit(void)
{
    PR_DEBUG("exiting module\n");
}

static int decrypt(char *message, int messageLength)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
   	struct skcipher_request *req = NULL;
	int rc = 0;

	int ret = -EFAULT;
	
	char *key_decrypt = NULL;
	char *iv_decrypt = NULL;
	char *scratchpad = NULL;
	char *result = NULL;

	int i;

	/* ==================== */

	/* Allocate a cipher handle for an skcipher */
	skcipher = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(skcipher)) {
		pr_info("could not allocate skcipher handle\n");
		return PTR_ERR(skcipher);
	}

	/* Allocate the request data structure that must be used with the skcipher encrypt and decrypt API calls */
	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		pr_info("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}
	
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, test_skcipher_cb, &sk.result);

	/* ==================== */

	/* Set key */
	key_decrypt = vmalloc(16);

	for(i = 0; i < 16; i++){
		key_decrypt[i] = key[i];
	}

	if (crypto_skcipher_setkey(skcipher, key_decrypt, 16)) {
   	     pr_err("fail setting key");
   	     goto out;
	}
	print_hex_dump(KERN_DEBUG, "Key_encrypt: ", DUMP_PREFIX_NONE, 16, 1, key_decrypt, 16, true);

	/* ==================== */

	iv_decrypt = vmalloc(16);

	if (!iv_decrypt) {
		pr_err("could not allocate iv vector\n");
		ret = -ENOMEM;
		goto out;
	}

	/* Preencher espaço alocado para iv */
	for(i = 0; i < 16; i++){
		iv_decrypt[i] = iv[i];
	}
		
	print_hex_dump(KERN_DEBUG, "IV Encrypt: ", DUMP_PREFIX_NONE, 16, 1, iv_decrypt, 16, true);

	/* ==================== */

	/* Set message */
	scratchpad = vmalloc(messageLength);
	if (!scratchpad) {
		pr_info("Could not allocate scratchpad\n");
		goto out;
	}
	
	/* Preencher espaço message */
	memcpy(scratchpad, message, messageLength);
	print_hex_dump(KERN_DEBUG, "Message: ", DUMP_PREFIX_NONE, 16, 1, scratchpad, 16, true);
	
	/* ==================== */

	/* Setando struct */
	sk.tfm = skcipher;
    	sk.req = req;


	/* Cifrar / Encrypt */
	sg_init_one(&sk.sg, scratchpad, 16);
	skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, iv_decrypt);
    	init_completion(&sk.result.completion);

	rc = crypto_skcipher_decrypt(req);
	
	if(rc){
		pr_info("skcipher encrypt returned with %d result %d\n", rc, sk.result.err);
		goto out;
	}

    	init_completion(&sk.result.completion);

	result = sg_virt(&sk.sg);
	print_hex_dump(KERN_DEBUG, "Result Data: ", DUMP_PREFIX_NONE, 16, 1, result, 16, true);
	
	/* ==================== */

	/* Out */
	out:
		if (skcipher) crypto_free_skcipher(skcipher);

		if (req) skcipher_request_free(req);

		if (key_decrypt) vfree(key_decrypt);

		if (iv_decrypt) vfree(iv_decrypt);

		if (scratchpad) vfree(scratchpad);

	return 0;
}

/* ================================================== */

static int hash(char *message, int messageLength)
{
	
	struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc init_sdesc(struct crypto_shash *alg)
{
    struct sdesc sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    sdesc->shash.flags = 0x0;
    return sdesc;
}

static int calc_hash(struct crypto_shashalg,
             const unsigned chardata, unsigned int datalen,
             unsigned chardigest) {
    struct sdesc sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("trusted_key: can't alloc %s\n", hash_alg);
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;

}


return 0;
}

module_init(crypto_init);
module_exit(crypto_exit);
