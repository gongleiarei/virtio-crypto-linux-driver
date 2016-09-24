/*
 * Algorithms supported by virtio crypto device
 *
 * Authors: Gonglei <arei.gonglei@huawei.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <linux/scatterlist.h>
#include <crypto/algapi.h>
#include <linux/err.h>
#include <crypto/scatterwalk.h>
#include <asm/atomic.h>

#include "virtio_crypto.h"
#include "virtio_crypto_common.h"

static DEFINE_MUTEX(algs_lock);
static unsigned int virtio_crypto_active_devs;

static u64 sg_nents_length(struct scatterlist *sg)
{
	u64 total;

	for (total = 0; sg; sg = sg_next(sg)) {
		total += sg->length;
	}

	return total;
}

static int virtio_crypto_alg_validate_key(int key_len, int *alg)
{
	switch (key_len) {
	case AES_KEYSIZE_128:
	case AES_KEYSIZE_192:
	case AES_KEYSIZE_256:
		*alg = VIRTIO_CRYPTO_CIPHER_AES_CBC;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int virtio_crypto_alg_ablkcipher_init_session(
		struct virtio_crypto_ablkcipher_ctx *ctx,
		int alg, const uint8_t *key,
		unsigned int keylen,
		int encrypt)
{
	struct scatterlist sg;
	unsigned int tmp;
	struct virtio_crypto_session_input *input;
	struct virtio_crypto_op_ctrl_req ctrl;
	struct virtio_crypto *vcrypto = ctx->vcrypto;
	int op = encrypt ? VIRTIO_CRYPTO_OP_ENCRYPT : VIRTIO_CRYPTO_OP_DECRYPT;
	int err;

	DPRINTK("Enter...\n");
	memset(&ctrl, 0, sizeof(ctrl));
	/* Pad ctrl header */
	ctrl.header.opcode = VIRTIO_CRYPTO_CIPHER_CREATE_SESSION;
	ctrl.header.algo = (uint32_t)alg;
	/* Set the default dataqueue id to 0 */
	ctrl.header.queue_id = 0;

	/* AES-CBC is a cipher algorithm */
	input = &ctrl.u.sym_create_session.u.cipher.input;
	input->status = VIRTIO_CRYPTO_ERR;
	/* Pad cipher's parameters */
	ctrl.u.sym_create_session.op_type = VIRTIO_CRYPTO_SYM_OP_CIPHER;
	ctrl.u.sym_create_session.u.cipher.para.algo = ctrl.header.algo;
	ctrl.u.sym_create_session.u.cipher.para.keylen = keylen;
	ctrl.u.sym_create_session.u.cipher.para.op = op;

	/* Pad cipher's output data */
	ctrl.u.sym_create_session.u.cipher.out.key_addr =
	                                            virt_to_phys((void *)key);

	sg_init_one(&sg, &ctrl, sizeof(ctrl));

	err = virtqueue_add_inbuf(vcrypto->ctrl_vq, &sg, 1, vcrypto, GFP_KERNEL);
	if (err < 0)
	    return err;
	virtqueue_kick(vcrypto->ctrl_vq);

	/*
	 * Spin for a response, the kick causes an ioport write, trapping
	 * into the hypervisor, so the request should be handled immediately.
	 */
	while (!virtqueue_get_buf(vcrypto->ctrl_vq, &tmp) &&
	       !virtqueue_is_broken(vcrypto->ctrl_vq))
		cpu_relax();

	if (input->status != VIRTIO_CRYPTO_OK) {
		printk(KERN_ERR "Create session failed "
			"status = %u, session_id=0x%llx\n", input->status,
			input->session_id);
		return -EINVAL;
	}

	DPRINTK("Create session successfully "
			"session_id=0x%llx\n", input->session_id);
	spin_lock(&ctx->lock);
	if (encrypt)
		ctx->enc_sess_info.session_id = input->session_id;
	else
		ctx->dec_sess_info.session_id = input->session_id;
	spin_unlock(&ctx->lock);

	DPRINTK("Exiting\n");
	return 0;
}

static int virtio_crypto_alg_ablkcipher_close_session(
		struct virtio_crypto_ablkcipher_ctx *ctx,
		int encrypt)
{
	struct scatterlist sg;
	unsigned int tmp;
	struct virtio_crypto_destroy_session_req *destroy_session;
	struct virtio_crypto_op_ctrl_req ctrl;
	struct virtio_crypto *vcrypto = ctx->vcrypto;
	int err;

	DPRINTK("Enter...\n");
	memset(&ctrl, 0, sizeof(ctrl));

	/* Pad ctrl header */
	ctrl.header.opcode = VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION;
	/* set the default virtqueue id to 0 */
	ctrl.header.queue_id = 0;

	destroy_session = &ctrl.u.destroy_session;

	if (encrypt)
		destroy_session->session_id = ctx->enc_sess_info.session_id;
	else
		destroy_session->session_id = ctx->dec_sess_info.session_id;

	DPRINTK("Close session, session_id=0x%llx\n",
			destroy_session->session_id);
	/* pass session id to host side so that host can close assigned session */
	sg_init_one(&sg, &ctrl, sizeof(ctrl));

	err = virtqueue_add_inbuf(vcrypto->ctrl_vq, &sg, 1, vcrypto, GFP_KERNEL);
	if (err < 0)
	    return err;
	virtqueue_kick(vcrypto->ctrl_vq);

	while (!virtqueue_get_buf(vcrypto->ctrl_vq, &tmp) &&
	       !virtqueue_is_broken(vcrypto->ctrl_vq))
		cpu_relax();

	if (destroy_session->status != VIRTIO_CRYPTO_OK) {
		printk(KERN_ERR "Close session failed "
			"status = %u, session_id=0x%llx\n", destroy_session->status,
			destroy_session->session_id);
		return -EINVAL;
	}

	DPRINTK("Exiting\n");
	return 0;
}

static int virtio_crypto_alg_ablkcipher_init_sessions(
					  struct virtio_crypto_ablkcipher_ctx *ctx,
					  const uint8_t *key, unsigned int keylen)
{
	int alg;
	int ret;

	if (virtio_crypto_alg_validate_key(keylen, &alg))
		goto bad_key;

	/* create encryption session */
	ret = virtio_crypto_alg_ablkcipher_init_session(ctx, alg, key, keylen, 1);
	if (ret)
		return ret;
	/* create decryption session */
	ret = virtio_crypto_alg_ablkcipher_init_session(ctx, alg, key, keylen, 0);
	if (ret) {
		virtio_crypto_alg_ablkcipher_close_session(ctx, 1);
		return ret;
	}
	return 0;

bad_key:
	crypto_tfm_set_flags(ctx->tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}

/* Note: kernel crypto API realization */
static int virtio_crypto_ablkcipher_setkey(struct crypto_ablkcipher *tfm,
					 const uint8_t *key,
					 unsigned int keylen)
{
	struct virtio_crypto_ablkcipher_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	int ret;

	DPRINTK("Enter...\n");

	spin_lock(&ctx->lock);

	if (!ctx->vcrypto) {
		/* new key */
		int node = get_current_node();
		struct virtio_crypto *vcrypto =
				      virtcrypto_get_dev_node(node);
		if (!vcrypto) {
			spin_unlock(&ctx->lock);
			return -EINVAL;
		}

		ctx->vcrypto = vcrypto;
	}
	spin_unlock(&ctx->lock);

	ret = virtio_crypto_alg_ablkcipher_init_sessions(ctx, key, keylen);
	if (ret) {
		virtcrypto_dev_put(ctx->vcrypto);
		ctx->vcrypto = NULL;

		return ret;
	}

	return 0;
}

static int
__virtio_crypto_ablkcipher_do_req(struct virtio_crypto_request *vc_req,
								struct ablkcipher_request *req, __u8 op)
{
	struct virtio_crypto_ablkcipher_ctx *ctx = vc_req->ablkcipher_ctx;
	struct virtio_crypto *vcrypto = ctx->vcrypto;
	struct virtio_crypto_op_data_req *req_data;
	int src_nents, dst_nents;
	int err;
	unsigned long flags;
	struct virtio_crypto_iovec *src_iovec = NULL;
	struct virtio_crypto_iovec *dst_iovec = NULL;
	struct scatterlist *sg;
	int i;
	u64 dst_len;

	/* Use the first data virtqueue as default */
	struct data_queue *data_vq = &vcrypto->data_vq[0];

	DPRINTK("Enter...\n");

	src_nents = sg_nents_for_len(req->src, req->nbytes);
	dst_nents = sg_nents(req->dst);

	DPRINTK("The number of scatterlist (src_nents"
			" = %d, dst_nents = %d)\n", src_nents, dst_nents);

	req_data = kzalloc_node(sizeof(*req_data), GFP_ATOMIC,
				           dev_to_node(&vcrypto->vdev->dev));
	if (!req_data) {
		printk(KERN_ERR "Failed to allocate memory.\n");
		return -ENOMEM;
	}

	vc_req->req_data = req_data;
	vc_req->type = VIRTIO_CRYPTO_SYM_OP_CIPHER;
	/* head of operation */
	if (op) {
		req_data->header.session_id = ctx->enc_sess_info.session_id;
		req_data->header.opcode = VIRTIO_CRYPTO_CIPHER_ENCRYPT;
	}
	else {
		req_data->header.session_id = ctx->dec_sess_info.session_id;
	    req_data->header.opcode = VIRTIO_CRYPTO_CIPHER_DECRYPT;
	}
	req_data->u.sym_req.op_type = VIRTIO_CRYPTO_SYM_OP_CIPHER;
	req_data->u.sym_req.u.cipher.para.iv_len = AES_BLOCK_SIZE;
	req_data->u.sym_req.u.cipher.para.src_data_len = req->nbytes;
	
	dst_len = sg_nents_length(req->dst);
	req_data->u.sym_req.u.cipher.para.dst_data_len = dst_len;
	DPRINTK("src_len: %u, dst_len: %llu\n", req->nbytes, dst_len);

	req_data->u.sym_req.u.cipher.odata.iv_addr = virt_to_phys(req->info);

	if (src_nents > 1) {
		src_iovec = kzalloc_node((src_nents - 1) * sizeof(*src_iovec), GFP_ATOMIC,
				           dev_to_node(&vcrypto->vdev->dev));
		if (!src_iovec) {
			printk(KERN_ERR "Failed to allocate memory.\n");
			kfree(req_data);
			return -ENOMEM;
		}
	}

	if (!src_iovec) { /* single sg */
		req_data->u.sym_req.u.cipher.odata.src_data.addr = sg_phys(req->src);
		req_data->u.sym_req.u.cipher.odata.src_data.len = req->nbytes;
		req_data->u.sym_req.u.cipher.odata.src_data.flags =
		                                      ~VIRTIO_CRYPTO_IOVEC_F_NEXT;
	} else { /* sg chain */
		req_data->u.sym_req.u.cipher.odata.src_data.addr = sg_phys(&req->src[0]);
		req_data->u.sym_req.u.cipher.odata.src_data.len = req->src[0].length;
		req_data->u.sym_req.u.cipher.odata.src_data.flags =
		                                      VIRTIO_CRYPTO_IOVEC_F_NEXT;
		req_data->u.sym_req.u.cipher.odata.src_data.next_iovec =
		                                        virt_to_phys(&src_iovec[0]);
		for (i = 0, sg = &req->src[1]; sg; sg = sg_next(sg), i++) {
			src_iovec[i].addr = sg_phys(sg);
			src_iovec[i].len = sg->length;
			if (i < (src_nents - 2)) {
				src_iovec[i].flags = VIRTIO_CRYPTO_IOVEC_F_NEXT;
				src_iovec[i].next_iovec = virt_to_phys(&src_iovec[i + 1]);
			} else 
				src_iovec[i].flags = ~VIRTIO_CRYPTO_IOVEC_F_NEXT;
		}
	}
	
	if (dst_nents > 1) {
		dst_iovec = kzalloc_node((dst_nents - 1) * sizeof(*dst_iovec), GFP_ATOMIC,
				           dev_to_node(&vcrypto->vdev->dev));
		if (!dst_iovec) {
			printk(KERN_ERR "Failed to allocate memory.\n");
			kfree(req_data);
			if (src_iovec)
				kfree(src_iovec);
			return -ENOMEM;
		}
	}

	if (!dst_iovec) { /* single sg */
		req_data->u.sym_req.u.cipher.idata.input.dst_data.addr = sg_phys(req->dst);
		req_data->u.sym_req.u.cipher.idata.input.dst_data.len = req->dst->length;
		req_data->u.sym_req.u.cipher.idata.input.dst_data.flags =
		                                        ~VIRTIO_CRYPTO_IOVEC_F_NEXT;
	} else { /* sg chain */
		
		req_data->u.sym_req.u.cipher.idata.input.dst_data.addr = sg_phys(&req->dst[0]);
		req_data->u.sym_req.u.cipher.idata.input.dst_data.len = req->dst[0].length;
		req_data->u.sym_req.u.cipher.idata.input.dst_data.flags =
		                                         VIRTIO_CRYPTO_IOVEC_F_NEXT;
		req_data->u.sym_req.u.cipher.idata.input.dst_data.next_iovec =
		                                           virt_to_phys(&dst_iovec[0]);
		for (i = 0, sg = &req->dst[1]; sg; sg = sg_next(sg), i++) {
			dst_iovec[i].addr = sg_phys(sg);
			dst_iovec[i].len = sg->length;
			if (i < (src_nents - 2)) {
				dst_iovec[i].flags = VIRTIO_CRYPTO_IOVEC_F_NEXT;
				dst_iovec[i].next_iovec = virt_to_phys(&dst_iovec[i + 1]);
			} else 
				dst_iovec[i].flags = ~VIRTIO_CRYPTO_IOVEC_F_NEXT;
		}
	}

	sg_set_buf(data_vq->sg, req_data, sizeof(*req_data));

	spin_lock_irqsave(&vcrypto->lock, flags);
	err = virtqueue_add_inbuf(vcrypto->data_vq->vq, data_vq->sg, 1,
	                          vc_req, GFP_ATOMIC);
	spin_unlock_irqrestore(&vcrypto->lock, flags);
	if (err < 0) {
		kfree(req_data);
		if (src_iovec)
			kfree(src_iovec);
		if (dst_iovec)
			kfree(dst_iovec);
		return err;
	}
	return 0;
}

static int virtio_crypto_ablkcipher_encrypt(struct ablkcipher_request *req)
{
	struct crypto_ablkcipher *atfm = crypto_ablkcipher_reqtfm(req);
	struct virtio_crypto_ablkcipher_ctx *ctx = crypto_ablkcipher_ctx(atfm);
	struct virtio_crypto_request *vc_req = ablkcipher_request_ctx(req);
	int ret;

	DPRINTK("Enter...\n");

	vc_req->ablkcipher_ctx = ctx;
	vc_req->ablkcipher_req = req;
	ret = __virtio_crypto_ablkcipher_do_req(vc_req, req, 1);
	if (ret < 0) {
		printk(KERN_ERR "Encryption failed!\n");
		return ret;
	}
	virtqueue_kick(ctx->vcrypto->data_vq->vq);
	DPRINTK("Exiting...\n");
	
	return -EINPROGRESS;
}

static int virtio_crypto_ablkcipher_decrypt(struct ablkcipher_request *req)
{
	struct crypto_ablkcipher *atfm = crypto_ablkcipher_reqtfm(req);
	struct virtio_crypto_ablkcipher_ctx *ctx = crypto_ablkcipher_ctx(atfm);
	struct virtio_crypto_request *vc_req = ablkcipher_request_ctx(req);
	int ret;

	DPRINTK("Enter...\n");

	vc_req->ablkcipher_ctx = ctx;
	vc_req->ablkcipher_req = req;

	ret = __virtio_crypto_ablkcipher_do_req(vc_req, req, 0);
	if (ret < 0) {
		printk(KERN_ERR "Decryption failed!\n");
		return ret;
	}
	virtqueue_kick(ctx->vcrypto->data_vq->vq);

	DPRINTK("Exiting\n");
	
	return -EINPROGRESS;
}

static int virtio_crypto_ablkcipher_init(struct crypto_tfm *tfm)
{
	struct virtio_crypto_ablkcipher_ctx *ctx = crypto_tfm_ctx(tfm);

	DPRINTK("Enter...\n");

	spin_lock_init(&ctx->lock);
	tfm->crt_ablkcipher.reqsize = sizeof(struct virtio_crypto_request);
	ctx->tfm = tfm;

	DPRINTK("Exiting\n");
	return 0;
}

static void virtio_crypto_ablkcipher_exit(struct crypto_tfm *tfm)
{
	struct virtio_crypto_ablkcipher_ctx *ctx = crypto_tfm_ctx(tfm);

	DPRINTK("Enter...\n");

	if (!ctx->vcrypto)
		return;

	virtio_crypto_alg_ablkcipher_close_session(ctx, 1);
	virtio_crypto_alg_ablkcipher_close_session(ctx, 0);
	virtcrypto_dev_put(ctx->vcrypto);
	ctx->vcrypto = NULL;

	DPRINTK("Exiting\n");
}

static struct crypto_alg virtio_crypto_algs[] = { {
	.cra_name = "cbc(aes)",
	.cra_driver_name = "virtio_crypto_aes_cbc",
	.cra_priority = 4001,
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize  = sizeof(struct virtio_crypto_ablkcipher_ctx),
	.cra_alignmask = 0,
	.cra_module = THIS_MODULE,
	.cra_type = &crypto_ablkcipher_type,
	.cra_init = virtio_crypto_ablkcipher_init,
	.cra_exit = virtio_crypto_ablkcipher_exit,
	.cra_u = {
	   .ablkcipher = {
			.setkey = virtio_crypto_ablkcipher_setkey,
			.decrypt = virtio_crypto_ablkcipher_decrypt,
			.encrypt = virtio_crypto_ablkcipher_encrypt,
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
			.ivsize = AES_BLOCK_SIZE,
		},
	},
} };

int virtio_crypto_algs_register(void)
{
	int ret = 0, i;

	mutex_lock(&algs_lock);
	if (++virtio_crypto_active_devs != 1)
		goto unlock;

	for (i = 0; i < ARRAY_SIZE(virtio_crypto_algs); i++) {
		virtio_crypto_algs[i].cra_flags =
			     CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC;
	}

	ret = crypto_register_algs(virtio_crypto_algs, 
	                           ARRAY_SIZE(virtio_crypto_algs)); 

unlock:
	mutex_unlock(&algs_lock);
	return ret;
}

void virtio_crypto_algs_unregister(void)
{
	mutex_lock(&algs_lock);
	if (--virtio_crypto_active_devs != 0)
		goto unlock;

	crypto_unregister_algs(virtio_crypto_algs, ARRAY_SIZE(virtio_crypto_algs));

unlock:
	mutex_unlock(&algs_lock);
}