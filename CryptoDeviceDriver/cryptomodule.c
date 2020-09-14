#include <linux/init.h>    
#include <linux/module.h>  
#include <linux/device.h>  
#include <linux/kernel.h>  
#include <linux/fs.h>      
#include <linux/uaccess.h> 
#include <linux/mutex.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/err.h>

#define DEVICE_NAME "crypto" /* /dev/crypto */
#define CLASS_NAME "cry"     /* The device class */

MODULE_LICENSE("GPL");                    
MODULE_AUTHOR("Cesar");                   
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

/** @brief This function is called whenever device is being read from user space i.e. data is
 *  being sent from the device to the user. In this case is uses the copy_to_user() function to
 *  send the buffer string to the user and captures any errors.
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 *  @param buffer The pointer to the buffer to which this function writes the data
 *  @param len The length of the b
 *  @param offset The offset if required
 */
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

/** @brief This function is called whenever the device is being written to from user space i.e.
 *  data is sent to the device from the user. The data is copied to the message[] array in this
 *  LKM using the sprintf() function along with the length of the string.
 *  @param filep A pointer to a file object
 *  @param buffer The buffer to that contains the string to write to the device
 *  @param len The length of the array of data that is being passed in the const char buffer
 *  @param offset The offset if required
 */
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
	sprintf(message, "%s", buffer); // appending received string with its length
	size_of_message = strlen(message);                // store the length of the stored message
	printk(KERN_INFO "Crypto Module: Received %zu characters from the user\n", len);

	switch(message[size_of_message - 1]){

		case 'c':
			printk("Cifrar mensagem");
			encrypt(message, size_of_message);
		break;
		
		case 'd':
			printk("Decifrar mensagem");
			decrypt(message, size_of_message);
		break;
		
		case 'h':
			printk("Hash mensagem");
			hash(message, size_of_message);
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
	return 0;
}


module_init(crypto_init);
module_exit(crypto_exit);
