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
#include <crypto/hash.h>

#define DEVICE_NAME "crypto" /* /dev/crypto */
#define CLASS_NAME "cry"	 /* The device class */
#define SHA1_SIZE 20

MODULE_LICENSE("GPL");
MODULE_AUTHOR("-----");
MODULE_DESCRIPTION("CryptoDeviceDriver");
MODULE_SUPPORTED_DEVICE("crypto");
MODULE_VERSION("1.0");

/* ================================================== */

static int majorNumber;					   /* device number -> determinado automaticamente */
static char message[258] = {0};			   /* string recebida do usuario (userspace) */
static int size_of_message;				   /* tamanho da string recebida do usuario */
static int numberOpens = 0;				   /* Vezes que o device foi aberto */
static struct class *cryptoClass = NULL;   /* device-driver class struct pointer */
static struct device *cryptoDevice = NULL; /* device-driver device struct pointer */
static DEFINE_MUTEX(crypto_mutex);

struct tcrypt_result
{
	struct completion completion;
	int err;
};

struct skcipher_def
{
	struct scatterlist sg;
	struct crypto_skcipher *skcipher;
	struct skcipher_request *req;
	struct tcrypt_result result;
};

/* ================================================== */

char *key;
char *iv;

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Chave para o algoritmo");
module_param(iv, charp, 0000);
MODULE_PARM_DESC(iv, "Vetor de inicialização para o algoritmo");

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
static void test_skcipher_cb(struct crypto_async_request *req, int error);
void clearMessage(char *message);

/* ================================================== */

static int __init crypto_init(void)
{
	printk(KERN_INFO "Crypto Module: Initializing the Crypto Module LKM\n");

	mutex_init(&crypto_mutex);

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
		class_destroy(cryptoClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		printk(KERN_ALERT "Failed to create the device\n");
		return PTR_ERR(cryptoDevice);
	}
	printk(KERN_INFO "Crypto Module: device class created correctly\n");

	return 0;
}

/* ================================================== */

static void __exit crypto_exit(void)
{
	mutex_destroy(&crypto_mutex);
	device_destroy(cryptoClass, MKDEV(majorNumber, 0));
	class_unregister(cryptoClass);
	class_destroy(cryptoClass);
	unregister_chrdev(majorNumber, DEVICE_NAME);
	printk(KERN_INFO "Crypto Module: Goodbye from the LKM!\n");
}

/* ================================================== */

static int dev_open(struct inode *inodep, struct file *filep)
{
	if (!mutex_trylock(&crypto_mutex))
	{
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

	// copy_to_user( * to, *from, size) and returns 0 on success
	clearMessage(buffer);
	error_count = copy_to_user(buffer, message, strlen(message));

	if (error_count == 0)
	{ // if true then have success
		return (size_of_message = 0);
	}
	else
	{
		return -EFAULT; // Failed -- return a bad address message (i.e. -14)
	}
}

/* ================================================== */

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
	clearMessage(message);
	sprintf(message, "%s", buffer);	   // appending received string with its length
	size_of_message = strlen(message); // store the length of the stored message
	//printk(KERN_INFO "Crypto Module: Received %zu characters from the user\n", len);

	switch (size_of_message - 1])
	{

	case 'c':
		encrypt(size_of_message - 2);
		break;

	case 'd':
		decrypt(size_of_message - 2);
		break;

	case 'h':
		hash(size_of_message - 2);
		break;
	}

	return len;
}

/* ================================================== */

static int dev_release(struct inode *inodep, struct file *filep)
{
	mutex_unlock(&crypto_mutex);
	//printk(KERN_INFO "Crypto Module: Device successfully closed\n");
	return 0;
}

/* ================================================== */

static int encrypt(char message[], int messageLength)
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

	/* ==================== */

	/* Allocate a cipher handle for an skcipher */
	skcipher = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(skcipher))
	{
		pr_info("could not allocate skcipher handle\n");
		return PTR_ERR(skcipher);
	}

	/* Allocate the request data structure that must be used with the skcipher encrypt and decrypt API calls */
	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req)
	{
		pr_info("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, test_skcipher_cb, &sk.result);

	/* ==================== */

	key_encrypt = vmalloc(16);

	strcpy(key_encrypt, key);

	if (crypto_skcipher_setkey(skcipher, key_encrypt, 16))
	{
		pr_err("fail setting key");
		goto out;
	}

	/* ==================== */

	iv_encrypt = vmalloc(16);

	if (!iv_encrypt)
	{
		pr_err("could not allocate iv vector\n");
		ret = -ENOMEM;
		goto out;
	}

	strcpy(iv_encrypt, iv);

	/* ==================== */

	scratchpad = vmalloc(messageLength);

	if (!scratchpad)
	{
		pr_info("Could not allocate scratchpad\n");
		goto out;
	}

	memcpy(scratchpad, message, messageLength);

	/* ==================== */

	/* Setando struct */
	sk.skcipher = skcipher;
	sk.req = req;

	/* Cifrar / Encrypt */
	sg_init_one(&sk.sg, scratchpad, 16);
	skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, iv_encrypt);
	init_completion(&sk.result.completion);

	rc = crypto_skcipher_encrypt(req);

	if (rc)
	{
		pr_info("skcipher encrypt returned with %d result %d\n", rc, sk.result.err);
		goto out;
	}

	init_completion(&sk.result.completion);

	result = sg_virt(&sk.sg);

	strcpy(message, result);
	printk("========================================");
	print_hex_dump(KERN_DEBUG, "Result Data Encrypt: ", DUMP_PREFIX_NONE, 16, 1, result, 16, true);
	printk("========================================");

	/* ==================== */

out:
	if (skcipher)
		crypto_free_skcipher(skcipher);

	if (req)
		skcipher_request_free(req);

	if (key_encrypt)
		vfree(key_encrypt);

	if (iv_encrypt)
		vfree(iv_encrypt);

	if (scratchpad)
		vfree(scratchpad);

	return 0;
}

/* ================================================== */

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

	/* ==================== */

	/* Allocate a cipher handle for an skcipher */
	skcipher = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(skcipher))
	{
		pr_info("could not allocate skcipher handle\n");
		return PTR_ERR(skcipher);
	}

	/* Allocate the request data structure that must be used with the skcipher encrypt and decrypt API calls */
	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req)
	{
		pr_info("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, test_skcipher_cb, &sk.result);

	/* ==================== */

	/* Set key */
	key_decrypt = vmalloc(16);

	strcpy(key_decrypt, key);

	if (crypto_skcipher_setkey(skcipher, key_decrypt, 16))
	{
		pr_err("fail setting key");
		goto out;
	}

	/* ==================== */

	iv_decrypt = vmalloc(16);

	if (!iv_decrypt)
	{
		pr_err("could not allocate iv vector\n");
		ret = -ENOMEM;
		goto out;
	}

	strcpy(iv_decrypt, iv);

	/* ==================== */

	/* Set message */
	scratchpad = vmalloc(messageLength);
	if (!scratchpad)
	{
		pr_info("Could not allocate scratchpad\n");
		goto out;
	}

	memcpy(scratchpad, message, messageLength);

	/* ==================== */

	/* Setando struct */
	sk.skcipher = skcipher;
	sk.req = req;

	/* Decifrar / Decrypt */
	sg_init_one(&sk.sg, scratchpad, 16);
	skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, iv_decrypt);
	init_completion(&sk.result.completion);

	rc = crypto_skcipher_decrypt(req);

	if (rc)
	{
		pr_info("skcipher encrypt returned with %d result %d\n", rc, sk.result.err);
		goto out;
	}

	init_completion(&sk.result.completion);

	result = sg_virt(&sk.sg);
	strcpy(message, result);

	printk("====================");
	print_hex_dump(KERN_DEBUG, "Result Data Decrypt: ", DUMP_PREFIX_NONE, 16, 1, result, 16, true);
	printk("====================");

	/* ==================== */

out:
	if (skcipher)
		crypto_free_skcipher(skcipher);

	if (req)
		skcipher_request_free(req);

	if (key_decrypt)
		vfree(key_decrypt);

	if (iv_decrypt)
		vfree(iv_decrypt);

	if (scratchpad)
		vfree(scratchpad);

	return 0;
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

	result = vmalloc(SHA1_SIZE);
	if (!result)
		goto out;

	ret = crypto_shash_digest(shash, message, messageLength, result);
	strcpy(message, result);

	printk("====================");
	print_hex_dump(KERN_DEBUG, "Result Data Hash: ", DUMP_PREFIX_NONE, 20, 1, result, 20, true);
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

/* ================================================== */

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

/* ================================================== */

void clearMessage(char *message)
{
	int i;
	for (i = 0; i < strlen(message); i++)
	{
		message[i] = '\0';
	}
}

/* ================================================== */

module_init(crypto_init);
module_exit(crypto_exit);
