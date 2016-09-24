/*
 * Virtio crypto device driver
 *
 * Authors: Gonglei <arei.gonglei@huawei.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <linux/err.h>
#include <linux/module.h>
#include <linux/virtio_config.h>
#include <linux/cpu.h>

#include "virtio_crypto.h"
#include "virtio_crypto_common.h"

#define VIRTIO_ID_CRYPTO 20

static void virtcrypto_dataq_callback(struct virtqueue *vq)
{
	struct virtio_crypto *vi = vq->vdev->priv;
	struct virtio_crypto_request *vc_req;
	unsigned long flags;
	unsigned int len;
	struct ablkcipher_request *ablk_req;
	int error;

	spin_lock_irqsave(&vi->lock, flags);
	do {
		virtqueue_disable_cb(vq);
		while ((vc_req = virtqueue_get_buf(vq, &len)) != NULL) {
			if (vc_req->type == VIRTIO_CRYPTO_SYM_OP_CIPHER) {
				switch (vc_req->req_data->u.sym_req.u.cipher.idata.input.status) {
				case VIRTIO_CRYPTO_OK:
					error = 0;
					break;
				case VIRTIO_CRYPTO_INVSESS:
				case VIRTIO_CRYPTO_ERR:
					error = -EINVAL;
					break;
				case VIRTIO_CRYPTO_BADMSG:
					error = -EBADMSG;
					break;
				default:
					error = -EIO;
					break;
				}
				DPRINTK("error: %d\n", error);

				ablk_req = vc_req->ablkcipher_req;
				/* Finish the encrypt or decrypt process */
				ablk_req->base.complete(&ablk_req->base, error);
			}
			
			kfree(vc_req->req_data);
		}
	} while (!virtqueue_enable_cb(vq));
	spin_unlock_irqrestore(&vi->lock, flags);
}

static int virtcrypto_find_vqs(struct virtio_crypto *vi)
{
	vq_callback_t **callbacks;
	struct virtqueue **vqs;
	int ret = -ENOMEM;
	int i, total_vqs;
	const char **names;

	/* We expect 1 data virtqueue, followed by
	 * possible N-1 data queues used in multiqueue mode, followed by
	 * control vq.
	 */
	total_vqs = vi->max_queues + 1;

	/* Allocate space for find_vqs parameters */
	vqs = kzalloc(total_vqs * sizeof(*vqs), GFP_KERNEL);
	if (!vqs)
		goto err_vq;
	callbacks = kmalloc(total_vqs * sizeof(*callbacks), GFP_KERNEL);
	if (!callbacks)
		goto err_callback;
	names = kmalloc(total_vqs * sizeof(*names), GFP_KERNEL);
	if (!names)
		goto err_names;

	/* Parameters for control virtqueue */
	callbacks[total_vqs - 1] = NULL;
	names[total_vqs - 1] = "controlq";

	/* Allocate/initialize parameters for data virtqueues */
	for (i = 0; i < vi->max_queues; i++) {
		callbacks[i] = virtcrypto_dataq_callback;
		snprintf(vi->data_vq[i].name, sizeof(vi->data_vq[i].name),
		         "dataq.%d", i);
		names[i] = vi->data_vq[i].name;
	}

	ret = vi->vdev->config->find_vqs(vi->vdev, total_vqs, vqs, callbacks,
					 names);
	if (ret)
		goto err_find;

	vi->ctrl_vq = vqs[total_vqs - 1];

	for (i = 0; i < vi->max_queues; i++) {
		vi->data_vq[i].vq = vqs[i];
	}

	kfree(names);
	kfree(callbacks);
	kfree(vqs);

	return 0;

err_find:
	kfree(names);
err_names:
	kfree(callbacks);
err_callback:
	kfree(vqs);
err_vq:
	return ret;
}

static int virtcrypto_alloc_queues(struct virtio_crypto *vi)
{
	int i;

	vi->data_vq = kzalloc(sizeof(*vi->data_vq) * vi->max_queues, GFP_KERNEL);
	if (!vi->data_vq)
		return -ENOMEM;

	for (i = 0; i < vi->max_queues; i++) {
		sg_init_table(vi->data_vq[i].sg, ARRAY_SIZE(vi->data_vq[i].sg));
	}

	return 0;
}

static void virtcrypto_clean_affinity(struct virtio_crypto *vi, long hcpu)
{
	int i;

	if (vi->affinity_hint_set) {
		for (i = 0; i < vi->max_queues; i++) {
			virtqueue_set_affinity(vi->data_vq[i].vq, -1);
		}

		vi->affinity_hint_set = false;
	}
}

static void virtcrypto_set_affinity(struct virtio_crypto *vi)
{
	int i;
	int cpu;

	/* In multiqueue mode, when the number of cpu is equal to the number of
	 * queue, we let the queue to be private to one cpu by
	 * setting the affinity hint to eliminate the contention.
	 */
	if (vi->curr_queue == 1 ||
	    vi->max_queues != num_online_cpus()) {
		virtcrypto_clean_affinity(vi, -1);
		return;
	}

	i = 0;
	for_each_online_cpu(cpu) {
		virtqueue_set_affinity(vi->data_vq[i].vq, cpu);
		i++;
	}

	vi->affinity_hint_set = true;
}

static void virtcrypto_free_queues(struct virtio_crypto *vi)
{
	kfree(vi->data_vq);
}

static int virtcrypto_init_vqs(struct virtio_crypto *vi)
{
	
	int ret;
	
	/* Allocate send & receive queues */
	ret = virtcrypto_alloc_queues(vi);
	if (ret)
		goto err;

	ret = virtcrypto_find_vqs(vi);
	if (ret)
		goto err_free;

	get_online_cpus();
	virtcrypto_set_affinity(vi);
	put_online_cpus();

	return 0;
	
err_free:
	virtcrypto_free_queues(vi);
err:
	return ret;
}

static void virtcrypto_update_status(struct virtio_crypto *vcrypto)
{
	u32 v;

	virtio_cread(vcrypto->vdev, struct virtio_crypto_config, status, &v);

	/* Ignore unknown (future) status bits */
	v &= VIRTIO_CRYPTO_S_HW_READY;

	if (vcrypto->status == v)
		return;

	vcrypto->status = v;

	if (vcrypto->status & VIRTIO_CRYPTO_S_HW_READY) {
		pr_info("virtio_crypto: accelerator is ready\n");
	} else {
		pr_info("virtio_crypto: accelerator is not ready\n");
	}
}

static int virtcrypto_probe(struct virtio_device *vdev)
{
	int err = -EFAULT;
	struct virtio_crypto *vcrypto;
	u32 max_queues;

	DPRINTK("Enter...\n");

	if (!vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
			__func__);
		return -EINVAL;
	}

	if (num_possible_nodes() > 1 && dev_to_node(&vdev->dev) < 0) {
		/* If the accelerator is connected to a node with no memory
		 * there is no point in using the accelerator since the remote
		 * memory transaction will be very slow. */
		dev_err(&vdev->dev, "Invalid NUMA configuration.\n");
		return -EINVAL;
	}

	virtio_cread(vdev, struct virtio_crypto_config,
	             max_dataqueues, &max_queues);
	if (max_queues < 1) {
		max_queues = 1;
	}
	dev_info(&vdev->dev, "max_queues: %u\n", max_queues);

	vcrypto = kzalloc_node(sizeof(*vcrypto), GFP_KERNEL,
				           dev_to_node(&vdev->dev));
	if (!vcrypto) {
		dev_err(&vdev->dev, "Failed to allocate memory.\n");
		return -ENOMEM;
	}
	/* Add virtio crypto device to global table */
	err = virtcrypto_devmgr_add_dev(vcrypto);
	if (err) {
		dev_err(&vdev->dev, "Failed to add new virtio crypto device.\n");
		goto free;
	}
	vcrypto->owner = THIS_MODULE;
	vcrypto = vdev->priv = vcrypto;
	vcrypto->vdev = vdev;
	spin_lock_init(&vcrypto->lock);

	/* Use sigle data queue as default */
	vcrypto->curr_queue = 1;
	vcrypto->max_queues = max_queues;

	err = virtcrypto_init_vqs(vcrypto);
	if (err) {
		dev_err(&vdev->dev, "Failed to initialize vqs.\n");
		goto free_dev;
	}
	virtio_device_ready(vdev);

	virtcrypto_update_status(vcrypto);

	if (vcrypto->status & VIRTIO_CRYPTO_S_HW_READY) {
		err = virtcrypto_dev_start(vcrypto);
		if (err) {
			dev_err(&vdev->dev, "Failed to start virtio crypto device.\n");
			goto free_start;
		}	
	} 

	DPRINTK("Exit...\n");
	return 0;

free_start:
	virtcrypto_dev_stop(vcrypto);
free_dev:
	virtcrypto_devmgr_rm_dev(vcrypto);
free:
	kfree(vcrypto);
	return err;
}

static void virtcrypto_del_vqs(struct virtio_crypto *vcrypto)
{
	struct virtio_device *vdev = vcrypto->vdev;

	virtcrypto_clean_affinity(vcrypto, -1);

	vdev->config->del_vqs(vdev);

	virtcrypto_free_queues(vcrypto);
}

static void virtcrypto_remove(struct virtio_device *vdev)
{
	struct virtio_crypto *vcrypto = vdev->priv;

	DPRINTK("Enter...");

	dev_err(&vdev->dev, "start virtcrypto_remove.\n");

	if (virtcrypto_dev_started(vcrypto))
		virtcrypto_dev_stop(vcrypto);
	vdev->config->reset(vdev);
	virtcrypto_del_vqs(vcrypto);
	virtcrypto_devmgr_rm_dev(vcrypto);
	kfree(vcrypto);
}

static void virtcrypto_config_changed(struct virtio_device *vdev)
{
	struct virtio_crypto *vcrypto = vdev->priv;

	virtcrypto_update_status(vcrypto);
}

static unsigned int features[] = {
	/* none */
};

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_CRYPTO, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_crypto_driver = {
	.driver.name         = KBUILD_MODNAME,
	.driver.owner        = THIS_MODULE,
	.feature_table       = features,
	.feature_table_size  = ARRAY_SIZE(features),
	.id_table            = id_table,
	.probe               = virtcrypto_probe,
	.remove              = virtcrypto_remove,
	.config_changed = virtcrypto_config_changed,
};

module_virtio_driver(virtio_crypto_driver);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("virtio crypto device driver");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gonglei <arei.gonglei@huawei.com>");
