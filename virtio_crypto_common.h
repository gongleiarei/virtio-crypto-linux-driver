#ifndef _VIRITO_CRYPTO_COMMON_H
#define _VIRITO_CRYPTO_COMMON_H

#include <linux/virtio.h>
#include <linux/crypto.h>
#include <linux/spinlock.h>
#include <crypto/aead.h>
#include <crypto/aes.h>
#include <crypto/sha.h>
#include <crypto/hash.h>
#include <crypto/authenc.h>

#include "virtio_crypto.h"

/*
 * Debugging
 */
 #define DEBUG_VIRTIO_CRYPTO

#ifdef DEBUG_VIRTIO_CRYPTO
#define DPRINTK(fmt,arg...) printk(KERN_ERR "%s: " fmt, __func__ , ##arg)
#else
#define DPRINTK(fmt,arg...) do { } while (0)
#endif


/* Internal representation of a data virtqueue */
struct data_queue {
	/* Virtqueue associated with this send _queue */
	struct virtqueue *vq;

	/* only one sg for each request */
	struct scatterlist sg[1];

	/* Name of the tx queue: dataq.$index */
	char name[32];
};

struct virtio_crypto {
	struct virtio_device *vdev;
	struct virtqueue *ctrl_vq;
	struct data_queue *data_vq;

	spinlock_t lock;

	/* Max # of queues supported by the device */
	u16 max_queues;

	/* # of queue currently used by the driver */
	u16 curr_queue;

	unsigned long status;
	atomic_t ref_count;
	struct list_head list;
	struct module *owner;
	uint8_t dev_id;

	/* Does the affinity hint is set for virtqueues? */
	bool affinity_hint_set;
};

typedef struct virtio_crypto_sym_session_info {
	/* the backend session id, which come from the host side */
	__u64 session_id;
} virtio_crypto_sym_session_info_t;

struct virtio_crypto_ablkcipher_ctx {
	struct virtio_crypto *vcrypto;
	struct crypto_tfm *tfm;
	uint8_t key[64];

	virtio_crypto_sym_session_info_t enc_sess_info;
	virtio_crypto_sym_session_info_t dec_sess_info;

	/* protects virtio_crypto_ablkcipher_ctx struct */
	spinlock_t lock;
};

struct virtio_crypto_request {
	/* cipher or aead */
	uint32_t type;
	uint32_t status;
	struct virtio_crypto_ablkcipher_ctx *ablkcipher_ctx;
	struct ablkcipher_request *ablkcipher_req;
	struct virtio_crypto_op_data_req *req_data;
	struct scatterlist **sgs;
};

int virtcrypto_devmgr_add_dev(struct virtio_crypto *vcrypto_dev);
struct list_head *virtcrypto_devmgr_get_head(void);
void virtcrypto_devmgr_rm_dev(struct virtio_crypto *vcrypto_dev);
struct virtio_crypto *virtcrypto_devmgr_get_first(void);
int virtcrypto_dev_in_use(struct virtio_crypto *vcrypto_dev);
int virtcrypto_dev_get(struct virtio_crypto *vcrypto_dev);
void virtcrypto_dev_put(struct virtio_crypto *vcrypto_dev);
int virtcrypto_dev_started(struct virtio_crypto *vcrypto_dev);
struct virtio_crypto *virtcrypto_get_dev_node(int node);
int virtcrypto_dev_start(struct virtio_crypto *vcrypto);
int virtcrypto_dev_stop(struct virtio_crypto *vcrypto);

static inline int get_current_node(void)
{
	return topology_physical_package_id(smp_processor_id());
}

int virtio_crypto_algs_register(void);
void virtio_crypto_algs_unregister(void);

#endif
