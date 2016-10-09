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
	struct scatterlist outhdr, key_sg, inhdr, *sgs[3];
	unsigned int tmp;
	struct virtio_crypto_session_input input;
	struct virtio_crypto_op_ctrl_req ctrl;
	struct virtio_crypto *vcrypto = ctx->vcrypto;
	int op = encrypt ? VIRTIO_CRYPTO_OP_ENCRYPT : VIRTIO_CRYPTO_OP_DECRYPT;
	int err;
	unsigned int num_out = 0, num_in = 0;

	DPRINTK("Enter...\n");

	memset(&ctrl, 0, sizeof(ctrl));
	memset(&input, 0, sizeof(input));
	/* Pad ctrl header */
	ctrl.header.opcode = VIRTIO_CRYPTO_CIPHER_CREATE_SESSION;
	ctrl.header.algo = (uint32_t)alg;
	/* Set the default dataqueue id to 0 */
	ctrl.header.queue_id = 0;

	input.status = VIRTIO_CRYPTO_ERR;
	/* Pad cipher's parameters */
	ctrl.u.sym_create_session.op_type = VIRTIO_CRYPTO_SYM_OP_CIPHER;
	ctrl.u.sym_create_session.u.cipher.para.algo = ctrl.header.algo;
	ctrl.u.sym_create_session.u.cipher.para.keylen = keylen;
	ctrl.u.sym_create_session.u.cipher.para.op = op;

	sg_init_one(&outhdr, &ctrl, sizeof(ctrl));
	sgs[num_out++] = &outhdr;

	/* Set key */
	sg_init_one(&key_sg, key, keylen);
	sgs[num_out++] = &key_sg;

	/* Return status and session id back */
	sg_init_one(&inhdr, &input, sizeof(input));
	sgs[num_out + num_in++] = &inhdr;

	err = virtqueue_add_sgs(vcrypto->ctrl_vq, sgs, num_out,
	                        num_in, vcrypto, GFP_KERNEL);
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

	if (input.status != VIRTIO_CRYPTO_OK) {
		printk(KERN_ERR "Create session failed "
			"status = %u, session_id=0x%llx\n", input.status,
			input.session_id);
		return -EINVAL;
	}

	DPRINTK("Create session successfully "
			"session_id=0x%llx\n", input.session_id);
	spin_lock(&ctx->lock);
	if (encrypt)
		ctx->enc_sess_info.session_id = input.session_id;
	else
		ctx->dec_sess_info.session_id = input.session_id;
	spin_unlock(&ctx->lock);

	DPRINTK("Exiting\n");
	return 0;
}

static int virtio_crypto_alg_ablkcipher_close_session(
		struct virtio_crypto_ablkcipher_ctx *ctx,
		int encrypt)
{
	struct scatterlist outhdr, status_sg, *sgs[2];
	unsigned int tmp;
	struct virtio_crypto_destroy_session_req *destroy_session;
	struct virtio_crypto_op_ctrl_req ctrl;
	struct virtio_crypto *vcrypto = ctx->vcrypto;
	int err;
	unsigned int num_out = 0, num_in = 0;
	uint32_t status = VIRTIO_CRYPTO_ERR;

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
	sg_init_one(&outhdr, &ctrl, sizeof(ctrl));
	sgs[num_out++] = &outhdr;

	/* Return status and session id back */
	sg_init_one(&status_sg, &status, sizeof(status));
	sgs[num_out + num_in++] = &status_sg;

	err = virtqueue_add_sgs(vcrypto->ctrl_vq, sgs, num_out,
	                        num_in, vcrypto, GFP_KERNEL);
	if (err < 0)
	    return err;
	virtqueue_kick(vcrypto->ctrl_vq);

	while (!virtqueue_get_buf(vcrypto->ctrl_vq, &tmp) &&
	       !virtqueue_is_broken(vcrypto->ctrl_vq))
		cpu_relax();

	if (status != VIRTIO_CRYPTO_OK) {
		printk(KERN_ERR "Close session failed "
			"status = %u, session_id=0x%llx\n", status,
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
	struct scatterlist outhdr, iv_sg, status_sg, **sgs;
	int i;
	u64 dst_len;
	unsigned int num_out = 0, num_in = 0;
	int sg_total;

	/* Use the first data virtqueue as default */
	struct data_queue *data_vq = &vcrypto->data_vq[0];

	DPRINTK("Enter...\n");

	src_nents = sg_nents_for_len(req->src, req->nbytes);
	dst_nents = sg_nents(req->dst);

	DPRINTK("The number of scatterlist (src_nents"
			" = %d, dst_nents = %d)\n", src_nents, dst_nents);

	/* why 3?  outhdr + iv + inhdr */
	sg_total = src_nents + dst_nents + 3;
	sgs = kzalloc_node(sg_total * sizeof(*sgs), GFP_ATOMIC,
				           dev_to_node(&vcrypto->vdev->dev));
	if (!sgs) {
		printk(KERN_ERR "Failed to allocate memory.\n");
		return -ENOMEM;
	}

	req_data = kzalloc_node(sizeof(*req_data), GFP_ATOMIC,
				           dev_to_node(&vcrypto->vdev->dev));
	if (!req_data) {
		printk(KERN_ERR "Failed to allocate memory.\n");
		kfree(sgs);
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

	/* Outhdr */
	sg_init_one(&outhdr, req_data, sizeof(*req_data));
	sgs[num_out++] = &outhdr;

	/* IV */
	sg_init_one(&iv_sg, req->info, req_data->u.sym_req.u.cipher.para.iv_len);
	sgs[num_out++] = &iv_sg;

	/* Source data */
	for (i = 0; i < src_nents; i++) {
		sgs[num_out++] = &req->src[i];
	}

	/* Destination data */
	for (i = 0; i < dst_nents; i++) {
		sgs[num_out + num_in++] = &req->dst[i];
	}

	/* Status */
	sg_init_one(&status_sg, &vc_req->status, sizeof(vc_req->status));
	sgs[num_out + num_in++] = &status_sg;

	vc_req->sgs = sgs;

	spin_lock_irqsave(&vcrypto->lock, flags);
	err = virtqueue_add_sgs(data_vq->vq, sgs, num_out,
	                        num_in, vc_req, GFP_KERNEL);
	spin_unlock_irqrestore(&vcrypto->lock, flags);
	if (err < 0) {
		kfree(req_data);
		kfree(sgs);
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