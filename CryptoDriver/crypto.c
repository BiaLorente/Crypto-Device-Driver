#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/uaccess.h>          // Required for the copy to user function

#include <linux/mutex.h>
#include <linux/moduleparam.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>

/*#include <crypto/hash.h>
#include <linux/stat.h>
#include <linux/random.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/vmalloc.h>*/

#define  DEVICE_NAME "cryptoTest"    ///< The device will appear at /dev/ebbchar using this value
#define  CLASS_NAME  "crypTest"        ///< The device class -- this is a character device driver
#define FILL_SG(sg,ptr,len)     do { (sg)->page = virt_to_page(ptr); (sg)->offset = offset_in_page(ptr); (sg)->length = len; } while (0)

MODULE_LICENSE("GPL");            ///< The license type -- this affects available functionality
MODULE_AUTHOR("Pedroit");    ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("CryptoModule for SOB - Project 1");  ///< The description -- see modinfo
MODULE_SUPPORTED_DEVICE("cryptoTest");
MODULE_VERSION("0.1"); 

static int    majorNumber;                  
static char   message[256] = {0};           
static short  size_of_message;              
static int    numberOpens = 0;              
static struct class*  ebbcharClass  = NULL; 
static struct device* ebbcharDevice = NULL; 
//DEFINE_MUTEX -> Declara e inicializa o mutex, normalmente utilizado para mutex utilizado de forma global
static DEFINE_MUTEX(teste_mutex);

char *key;
char *iv;

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

static void hexdump(unsigned char *buf, unsigned int len)
{
        while (len--)
                //printk algo

        printk("\n");
}

 if (ret) {
                printk(KERN_ERR PFX "encryption failed"); //Erro na criptografia
                goto out_kfree;
        }

static int __init cripty_init(void) {

mutex_init(&teste_mutex);

majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "EBBChar failed to register a major number\n");
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
      class_destroy(ebbcharClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(ebbcharDevice);
   }
   printk(KERN_INFO "EBBChar: device class created correctly\n"); // Made it! device was initialized
   return 0;
}

}


static void __exit cripty_exit(void){
   mutex_destroy(&ebbchar_mutex);                           // destroy the dynamically-allocated mutex
   device_destroy(ebbcharClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(ebbcharClass);                          // unregister the device class
   class_destroy(ebbcharClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
}

static int dev_open(struct inode *inodep, struct file *filep){
   mutex_lock(&teste_mutex);
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
      printk(KERN_INFO "EBBChar: Failed to send %d characters to the user\n", error_count);
      return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
   }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
   sprintf(message, "%s", buffer);   
   size_of_message = strlen(message);                 // store the length of the stored message
   return len;
}

static int dev_release(struct inode *inodep, struct file *filep){
   mutex_unlock(&teste_mutex);
   printk(KERN_INFO "EBBChar: Device successfully closed\n");
   return 0;
}

module_init(cripty_init);
module_exit(cripty_exit);

