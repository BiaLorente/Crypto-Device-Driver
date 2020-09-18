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
#include <linux/mutex.h>	         /// Required for the mutex functionality
#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/uaccess.h>          // Required for the copy to user function
#define  DEVICE_NAME "crypto"    ///< The device will appear at /dev/crypto using this value
#define  CLASS_NAME  "cry"        ///< The device class -- this is a character device driver

MODULE_LICENSE("GPL");            ///< The license type -- this affects available functionality
MODULE_AUTHOR("BIA LORENTE");    ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple Linux crypto driver");  ///< The description -- see modinfo
MODULE_VERSION("0.1");            ///< A version number to inform users

static DEFINE_MUTEX(crypto_mutex);  /// A macro that is used to declare a new mutex that is visible in this file
                                     /// results in a semaphore variable crypto_mutex with value 1 (unlocked)
                                     /// DEFINE_MUTEX_LOCKED() results in a variable with value 0 (locked)

static int majorNumber;                    /* device number -> determinado automaticamente */
static char   message[256] = {0};           ///< Memory for the string that is passed from userspace
static short  size_of_message;              ///< Used to remember the size of the string stored
static int    numberOpens = 0;              ///< Counts the number of times the device is opened
static struct class*  cryptoClass  = NULL; ///< The device-driver class struct pointer
static struct device* cryptoDevice = NULL; ///< The device-driver device struct pointer

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

/** @brief A module must use the module_init() module_exit() macros from linux/init.h, which
 *  identify the initialization function at insertion time and the cleanup function (as
 *  listed above)
 */
module_init(crypto_init);
module_exit(crypto_exit);
