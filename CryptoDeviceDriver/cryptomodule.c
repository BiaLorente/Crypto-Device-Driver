/*
 *  Módulo de kernel para criptografia 
 */

/* insmod cryptomodule.ko key=”0123456789ABCDEF” iv=”0123456789ABCDEF” */

#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("----");
MODULE_DESCRIPTION("Modulo de criptografia");
MODULE_VERSION("1");

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations chardev_fops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release
};

int init_module(void)
{
    pr_info("Hello world\n");
    return 0;
}

void cleanup_module(void)
{
    pr_info("Goodbye world\n");
}