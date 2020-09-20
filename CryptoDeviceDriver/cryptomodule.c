#include <linux/init.h>          
#include <linux/module.h>         
#include <linux/device.h>         
#include <linux/kernel.h>         
#include <linux/fs.h>            
#include <linux/uaccess.h>       
#include <linux/mutex.h>	  
#include <linux/moduleparam.h>
#include <crypto/hash.h>
#include <linux/stat.h>
#include <linux/crypto.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/vmalloc.h>

#define DEVICE_NAME "crypto" /* /dev/crypto */
#define CLASS_NAME "cry"     /* The device class */

MODULE_LICENSE("GPL");                    
MODULE_AUTHOR("-----");                   
MODULE_DESCRIPTION("CryptoDeviceDriver"); 
MODULE_SUPPORTED_DEVICE("crypto");
MODULE_VERSION("1.0");                    

/* ================================================== */

static int majorNumber;                    /* device number -> determinado automaticamente */
static char message[256] = {0};            /* string recebida do usuario (userspace) */
static short size_of_message;              /* tamanho da string recebida do usuario */
static int numberOpens = 0;                /* Vezes que o device foi aberto */
static struct class *cryptoClass = NULL;   /* device-driver class struct pointer */
static struct device *cryptoDevice = NULL; /* device-driver device struct pointer */
static DEFINE_MUTEX(crypto_mutex);	

struct tcrypt_result {
    struct completion completion;
    int err;
};

struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};

/* ================================================== */

//insmod cryptomodule.ko key=”0123456789ABCDEF” iv=”0123456789ABCDEF”

char *key;
char *iv;

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Chave para o algoritmo AES-CBC");
module_param(iv, charp, 0000);
MODULE_PARM_DESC(iv, "Vetor de inicialização para o algoritmo AES-CBC");

/* ================================================== */

/* prototype functions -> character driver */ 
static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops = {
	.open = dev_open,
        .read = dev_read,
        .write = dev_write,
        .release = dev_release,
};

/* ================================================== */

static int encrypt(char *message, int messageLength);
static void test_skcipher_cb(struct crypto_async_request *req, int error);
static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc);

static int decrypt(char *message, int messageLength);
static int hash(char *message, int messageLength);

/* ================================================== */

static int __init crypto_init(void)
{
	printk(KERN_INFO "Crypto Module: Initializing the Crypto Module LKM\n");

	mutex_init(&crypto_mutex);

	// Try to dynamically allocate a major number for the device
	majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
	if (majorNumber < 0)
	{
		printk(KERN_ALERT "Crypto Module failed to register a major number\n");
   	     return majorNumber;
	}
   	 printk(KERN_INFO "Crypto Module: registered correctly with major number %d\n", majorNumber);

	// Register the device class
	cryptoClass = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(cryptoClass))
	{ // Check for error and clean up if there is
        	unregister_chrdev(majorNumber, DEVICE_NAME);
        	printk(KERN_ALERT "Failed to register device class\n");
        	return PTR_ERR(cryptoClass); // Correct way to return an error on a pointer
	}
	printk(KERN_INFO "Crypto Module: device class registered correctly\n");

	// Register the device driver
	cryptoDevice = device_create(cryptoClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
	if (IS_ERR(cryptoDevice))
	{
        	// Clean up if there is an error
        	class_destroy(cryptoClass); // Repeated code but the alternative is goto statements
        	unregister_chrdev(majorNumber, DEVICE_NAME);
        	printk(KERN_ALERT "Failed to create the device\n");
        	return PTR_ERR(cryptoDevice);
	}
	printk(KERN_INFO "Crypto Module: device class created correctly\n"); // Made it! device was initialized
	
	return 0;
}

/* ================================================== */

static void __exit crypto_exit(void)
{
	mutex_destroy(&crypto_mutex);
	device_destroy(cryptoClass, MKDEV(majorNumber, 0)); // remove the device
	class_unregister(cryptoClass);                      // unregister the device class
	class_destroy(cryptoClass);                         // remove the device class
	unregister_chrdev(majorNumber, DEVICE_NAME);        // unregister the major number
	printk(KERN_INFO "Crypto Module: Goodbye from the LKM!\n");
}

/* ================================================== */

static int dev_open(struct inode *inodep, struct file *filep)
{
	if (!mutex_trylock(&crypto_mutex))
	{ /// Try to acquire the mutex (i.e., put the lock on/down)
		/// returns 1 if successful and 0 if there is contention
        	printk(KERN_ALERT "Crypto Module: Device in use by another process");
        	return -EBUSY;
	}

	numberOpens++;
	printk(KERN_INFO "Crypto Module: Device has been opened %d time(s)\n", numberOpens);
	return 0;
}

/* ================================================== */

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset)
{
	int error_count = 0;
	// copy_to_user has the format ( * to, *from, size) and returns 0 on success
	error_count = copy_to_user(buffer, message, size_of_message);

	if (error_count == 0)
	{ // if true then have success
		printk(KERN_INFO "Crypto Module: Sent %d characters to the user\n", size_of_message);
		return (size_of_message = 0); // clear the position to the start and return 0
	}
	else
	{
		printk(KERN_INFO "Crypto Module: Failed to send %d characters to the user\n", error_count);
		return -EFAULT; // Failed -- return a bad address message (i.e. -14)
	}
}

/* ================================================== */

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
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

/* ================================================== */

static int dev_release(struct inode *inodep, struct file *filep)
{
	mutex_unlock(&crypto_mutex);
    	printk(KERN_INFO "Crypto Module: Device successfully closed\n");
    	return 0;
}

/* ================================================== */

static int encrypt(char message[], int messageLength)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
   	struct skcipher_request *req = NULL;
	
	int ret = -EFAULT;
	
	char *iv_encrypt = NULL;
	char *scratchpad = NULL;
	char *result = NULL;
	char *key_encrypt = NULL;

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
	for(i = 0; i < 16; i++){
		key_encrypt[i] = key[i];	
	}
	if (crypto_skcipher_setkey(skcipher, key_encrypt, 16)) {
   	     pr_err("fail setting key");
   	     goto out;
	}

	/* ==================== */

	/* Set iv */
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

	/* ==================== */

	/* Set message */
	scratchpad = vmalloc(messageLength);
	if (!scratchpad) {
		pr_info("Could not allocate scratchpad\n");
		goto out;
	}

	/* Preencher espaço alocado para scratchpad(message) */
	for(i = 0; i < messageLength; i++){
		scratchpad[i] = message[i];
	}

	/* ==================== */

	/* Setando struct */
	sk.tfm = skcipher;
    	sk.req = req;

	/* ==================== */

	/* Cifrar / Encrypt */
	sg_init_one(&sk.sg, scratchpad, 16);
	skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, iv_encrypt);
    	init_completion(&sk.result.completion);

	ret = test_skcipher_encdec(&sk, 1);
    	if (ret){
        	goto out;
	}

	/* ==================== */

	result = sg_virt(&sk.sg);
	pr_info("String cifrada: %s", result);
	
	/* ==================== */

	/* Out */
	out:
		if (skcipher)
	   	     	crypto_free_skcipher(skcipher);
		if (req)
			skcipher_request_free(req);
		//if (key_encrypt)
			//vfree(key_encrypt);
		if (iv_encrypt)
	      		vfree(iv_encrypt);
		if (scratchpad)
	    	    vfree(scratchpad);

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
	pr_info("Encryption finished successfully\n");
}

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc)
{
    int rc = 0;

    if (enc)
        rc = crypto_skcipher_encrypt(sk->req);
    else
        rc = crypto_skcipher_decrypt(sk->req);

    switch (rc) {
    	case 0:
        	break;
   	
	case -EINPROGRESS:

    	case -EBUSY:
		rc = wait_for_completion_interruptible(&sk->result.completion);
		if (!rc && !sk->result.err) {
		    reinit_completion(&sk->result.completion);
		    break;
		}

    	default:
		pr_info("skcipher encrypt returned with %d result %d\n", rc, sk->result.err);
        	break;
    }

    init_completion(&sk->result.completion);

    return rc;
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
