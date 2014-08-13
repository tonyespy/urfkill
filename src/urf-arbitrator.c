/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
 * Copyright (C) 2006-2009 Bastien Nocera <hadess@hadess.net>
 * Copyright (C) 2010-2011 Gary Ching-Pang Lin <glin@suse.com>
 * Copyright (C) 2014 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <glib.h>

#ifndef RFKILL_EVENT_SIZE_V1
#define RFKILL_EVENT_SIZE_V1    8
#endif

#include "urf-config.h"
#include "urf-arbitrator.h"
#include "urf-killswitch.h"
#include "urf-utils.h"

#include "urf-device.h"
#include "urf-device-kernel.h"

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	DEVICE_CHANGED,
	LAST_SIGNAL
};

static int signals[LAST_SIGNAL] = { 0 };

#define URF_ARBITRATOR_GET_PRIVATE(obj) (G_TYPE_INSTANCE_GET_PRIVATE((obj), \
                                URF_TYPE_ARBITRATOR, UrfArbitratorPrivate))

struct UrfArbitratorPrivate {
	int		 fd;
	UrfConfig	*config;
	gboolean	 force_sync;
	gboolean	 persist;
	GIOChannel	*channel;
	guint		 watch_id;
	GList		*devices; /* a GList of UrfDevice */
	UrfKillswitch	*killswitch[NUM_RFKILL_TYPES];
	GTask           *flight_mode_task;
	GTask           *pending_block_task;
	int              block_index;
	gboolean         pending_block;
};

G_DEFINE_TYPE(UrfArbitrator, urf_arbitrator, G_TYPE_OBJECT)

static void
urf_arbitrator_flight_mode_cb (GObject *source,
			       GAsyncResult *res,
			       gpointer user_data);

/**
 * urf_arbitrator_find_device:
 **/
static UrfDevice *
urf_arbitrator_find_device (UrfArbitrator *arbitrator,
                            gint           index)
{
	UrfArbitratorPrivate *priv = arbitrator->priv;
	UrfDevice *device;
	GList *item;

	g_return_val_if_fail (index >= 0, NULL);

	for (item = priv->devices; item != NULL; item = item->next) {
		device = (UrfDevice *)item->data;
		if (urf_device_get_index (device) == index)
			return device;
	}

	return NULL;
}

/**
 * urf_arbitrator_set_block:
 **/
void
urf_arbitrator_set_block (UrfArbitrator  *arbitrator,
			  const gint      type,
			  const gboolean  block,
			  GTask          *task)
{
	UrfArbitratorPrivate *priv = arbitrator->priv;

	g_return_val_if_fail (type >= 0, FALSE);
	g_return_val_if_fail (type < NUM_RFKILL_TYPES, FALSE);

	g_message ("%s: Setting %s devices to %s",
		   __func__,
                   type_to_string (type),
                   block ? "blocked" : "unblocked");

	urf_killswitch_set_software_blocked (priv->killswitch[type], block, task);
}

/**
 * urf_arbitrator_set_block_idx:
 **/
gboolean
urf_arbitrator_set_block_idx (UrfArbitrator  *arbitrator,
			      const gint      index,
			      const gboolean  block)
{
	UrfDevice *device;
	gboolean result = FALSE;

	g_return_val_if_fail (index >= 0, FALSE);

	device = urf_arbitrator_find_device (arbitrator, index);

	if (device) {
		g_message ("%s: Setting device %u (%s) to %s",
			   __func__,
                           index,
                           type_to_string (urf_device_get_device_type (device)),
                           block ? "blocked" : "unblocked");

		// AWE: fix
		urf_device_set_software_blocked (device, block, NULL);
	} else {
		g_warning ("Block index: No device with index %u", index);
	}

	return result;
}

// AWE: ADD pull-request #8 logic here!!!

/**
 * handle_flight_mode_killswitch
 **/
static gboolean
handle_flight_mode_killswitch(UrfArbitrator  *arbitrator, const gboolean block)
{
	UrfArbitratorPrivate *priv = arbitrator->priv;
	int i = priv->block_index++;

	// AWE: this calls urf_killswitch_state_refresh()
	KillswitchState state = urf_killswitch_get_state (priv->killswitch[i]);
	KillswitchState saved_state = KILLSWITCH_STATE_NO_ADAPTER;
	gboolean want_state = FALSE;

	if (state != KILLSWITCH_STATE_NO_ADAPTER) {
		g_message("%s: killswitch[%s] state: %s", __func__,
			  type_to_string(i),
			  state_to_string(state));

		saved_state = urf_killswitch_get_saved_state(priv->killswitch[i]);
		g_debug("saved_state is: %s", state_to_string(saved_state));


		// this updates saved before knowing that set_block worked
		// probably not a bad thing, but again not obvious
		//
		if (block)
			urf_killswitch_set_saved_state(priv->killswitch[i], state);

		// It'd be nice to simplify this a bit... It's pretty hard to
		// understand


		// also, if (unblock == FALSE && saved_state != state) this code
		// relies on the value of want_state from the previous loop iteration
		// as want_state is only initialized at the start of the function!!
		//
		// otherwise if saved_state && state are both SOFT or HARD_BLOCK, then
		// want_state is set to BLOCK.  If a device ( !GSM ) was blocked before
		// FM is enabled, this prevents it from being unblocked when FM is
		// disabled.

		if (!block && state == saved_state)
			want_state = (gboolean)(saved_state > KILLSWITCH_STATE_UNBLOCKED);
		else
			want_state = block;

		g_debug ("calling set_block %s %s",
			 type_to_string(i),
			 want_state ? "TRUE" : "FALSE");

		// FIXME: how is task cleaned up???
		priv->pending_block_task = g_task_new(arbitrator,
						      NULL,
						      urf_arbitrator_flight_mode_cb,
						      GINT_TO_POINTER(i));

		// In order to mimic the existing code, this routine needs to call
		// the first killswitch block, and then wait for a cb.
		// If the cb is OK, then it calls the next block, and so on...
		// If the cb fails, then we're done, and the daemon cb gets invoked

		urf_arbitrator_set_block (arbitrator, i, want_state, priv->pending_block_task);

		// indicates loop should stop
		return FALSE;
	} else {
		g_message("%s: killswitch[%s] state: %s", __func__,
			  type_to_string(i),
			  state_to_string(state));

		urf_config_set_persist_state(priv->config, i, block);

		// indicates loop can continue
		return TRUE;
	}
}


/**
 * urf_arbitrator_flight_mode_cb:
 **/
static void
urf_arbitrator_flight_mode_cb (GObject *source,
			       GAsyncResult *res,
			       gpointer user_data)
{
	UrfArbitrator  *arbitrator;
	UrfArbitratorPrivate *priv;
	GError            *error = NULL;
	int i;

	g_assert (URF_IS_ARBITRATOR (source));
	arbitrator = URF_ARBITRATOR (source);

	priv = arbitrator->priv;

	g_message ("%s", __func__);  // AWE

	g_assert (g_task_is_valid(res, source));
	g_assert (G_TASK(res) == G_TASK(priv->pending_block_task));

	priv->pending_block_task = NULL;
	i = GPOINTER_TO_INT(g_task_get_task_data(G_TASK (res)));

	// AWE: pointer is always NULL on success...
	g_task_propagate_pointer(G_TASK (res), &error);

	if (error != NULL) {
		g_message ("%s *error != NULL (Failed)", __func__);  // AWE

		if (priv->flight_mode_task != NULL)
			g_task_return_new_error(priv->flight_mode_task,
						error->domain, error->code,
						"set_block failed: %s",
						type_to_string(i));

		g_error_free (error);
		error = NULL;

		// AWE: want_state isn't available in the cb w/out extra work.
		//					want_state ? "TRUE" : "FALSE");

		priv->flight_mode_task = NULL;

	} else if (priv->block_index == NUM_RFKILL_TYPES) {
		g_message ("%s: block_index: %d; all done",
			   __func__, priv->block_index);  // AWE

		if (priv->flight_mode_task != NULL) {
			g_message ("%s: firing flight_mode_task", __func__);

			g_task_return_pointer (priv->flight_mode_task, NULL, NULL);
			priv->flight_mode_task = NULL;
		}
	} else {
		g_message("%s: more killswitches to process - next_idx: %d", __func__,
			  priv->block_index);

		for (; priv->block_index < NUM_RFKILL_TYPES;)
			if (!handle_flight_mode_killswitch(arbitrator, priv->pending_block))
				break;

		// trigger flight_mode task if last killswitch was NO_ADAPTER case
		if (priv->pending_block_task == NULL) {
			g_message ("%s  pending_block_task is NULL", __func__);  // AWE

			if (priv->flight_mode_task) {
				g_task_return_pointer (priv->flight_mode_task, NULL, NULL);
				priv->flight_mode_task = NULL;
			}
		}
	}

}

/**
 * urf_arbitrator_set_flight_mode:
 **/

/*
 * FIXME: inconsistent naming; this function should just be called
 * urf_arbitrator_flight_mode() to match urf_daemon_flight_mode().
 */
void
urf_arbitrator_set_flight_mode (UrfArbitrator  *arbitrator,
				const gboolean  block,
				GTask *task)
{
	UrfArbitratorPrivate *priv = arbitrator->priv;

	g_message("%s: block: %d", __func__, (int) block);

	priv->flight_mode_task = task;
	priv->pending_block_task = NULL;
	priv->pending_block = block;

	for (priv->block_index = RFKILL_TYPE_ALL + 1;
	     priv->block_index < NUM_RFKILL_TYPES;)
		if (!handle_flight_mode_killswitch(arbitrator, block))
			break;

	g_message("%s: handle_flight_mode_killswitch returned FALSE", __func__);

	// AWE: handle case where all adapters are missing
	if (priv->pending_block_task == NULL && priv->flight_mode_task != NULL) {
			g_message("%s: no pending_block_task - firing fm_task", __func__);
			g_task_return_pointer (priv->flight_mode_task, NULL, NULL);
			priv->flight_mode_task = NULL;
	}
}

/**
 * urf_arbitrator_get_state:
 **/
KillswitchState
urf_arbitrator_get_state (UrfArbitrator *arbitrator,
			  gint           type)
{
	UrfArbitratorPrivate *priv;
	int state = KILLSWITCH_STATE_NO_ADAPTER;

	g_return_val_if_fail (URF_IS_ARBITRATOR (arbitrator), state);
	g_return_val_if_fail (type >= 0, state);
	g_return_val_if_fail (type < NUM_RFKILL_TYPES, state);

	priv = arbitrator->priv;

	if (type == RFKILL_TYPE_ALL)
		type = RFKILL_TYPE_WLAN;
	state = urf_killswitch_get_state (priv->killswitch[type]);

	g_debug ("devices %s state %s",
		 type_to_string (type), state_to_string (state));

	return state;
}

/**
 * urf_arbitrator_get_state_idx:
 **/
KillswitchState
urf_arbitrator_get_state_idx (UrfArbitrator *arbitrator,
			      gint           index)
{
	UrfArbitratorPrivate *priv;
	UrfDevice *device;
	int state = KILLSWITCH_STATE_NO_ADAPTER;

	g_return_val_if_fail (URF_IS_ARBITRATOR (arbitrator), state);
	g_return_val_if_fail (index >= 0, state);

	priv = arbitrator->priv;

	if (priv->devices == NULL)
		return state;

	device = urf_arbitrator_find_device (arbitrator, index);
	if (device) {
		state = urf_device_get_state (device);
		g_debug ("killswitch %d is %s", index, state_to_string (state));
	}

	return state;
}

/**
 * urf_arbitrator_add_device:
 **/
gboolean
urf_arbitrator_add_device (UrfArbitrator *arbitrator, UrfDevice *device)
{
	UrfArbitratorPrivate *priv;
	gint type;
	gint index;
	gboolean soft;

	g_return_val_if_fail (URF_IS_ARBITRATOR (arbitrator), FALSE);
	g_return_val_if_fail (URF_IS_DEVICE (device), FALSE);

	priv = arbitrator->priv;
	type = urf_device_get_device_type (device);
	index = urf_device_get_index (device);
	soft = urf_device_is_software_blocked (device);

	priv->devices = g_list_append (priv->devices, device);

	urf_killswitch_add_device (priv->killswitch[type], device);

	if (priv->force_sync && !urf_device_is_platform (device)) {
		urf_arbitrator_set_block_idx (arbitrator, index, soft);
	}

	if (priv->persist) {
		/* use the saved persistence state as a default state to
		 * use for the new killswitch.
		 *
		 * This makes sure devices that appear after urfkill has
		 * started still get to the right state from what was saved
		 * to the persistence file.
		 */
		soft = urf_config_get_persist_state (priv->config, type);
		urf_arbitrator_set_block_idx (arbitrator, index, soft);
	}

	g_signal_emit (G_OBJECT (arbitrator), signals[DEVICE_ADDED], 0,
		       urf_device_get_object_path (device));

	return TRUE;
}

/**
 * urf_arbitrator_remove_device:
 **/
gboolean
urf_arbitrator_remove_device (UrfArbitrator *arbitrator, UrfDevice *device)
{
	gint type;

	g_return_val_if_fail (URF_IS_ARBITRATOR (arbitrator), FALSE);
	g_return_val_if_fail (URF_IS_DEVICE (device), FALSE);

	type = urf_device_get_device_type (device);

	g_return_val_if_fail (type >= 0, FALSE);

	arbitrator->priv->devices = g_list_remove (arbitrator->priv->devices, device);

	urf_killswitch_del_device (arbitrator->priv->killswitch[type], device);

	g_signal_emit (G_OBJECT (arbitrator), signals[DEVICE_REMOVED], 0,
	               urf_device_get_object_path (device));

	return TRUE;
}

/**
 * urf_arbitrator_has_devices:
 **/
gboolean
urf_arbitrator_has_devices (UrfArbitrator *arbitrator)
{
	g_return_val_if_fail (URF_IS_ARBITRATOR (arbitrator), FALSE);

	return (arbitrator->priv->devices != NULL);
}

/**
 * urf_arbitrator_get_devices:
 **/
GList*
urf_arbitrator_get_devices (UrfArbitrator *arbitrator)
{
	g_return_val_if_fail (URF_IS_ARBITRATOR (arbitrator), NULL);

	return arbitrator->priv->devices;
}

/**
 * urf_arbitrator_get_arbitrator:
 **/
UrfDevice *
urf_arbitrator_get_device (UrfArbitrator *arbitrator,
			   const gint     index)
{
	UrfDevice *device;

	g_return_val_if_fail (URF_IS_ARBITRATOR (arbitrator), NULL);
	g_return_val_if_fail (index >= 0, NULL);

	device = urf_arbitrator_find_device (arbitrator, index);
	if (device)
		return URF_DEVICE (g_object_ref (device));

	return NULL;
}

/**
 * update_killswitch:
 **/
static void
update_killswitch (UrfArbitrator *arbitrator,
		   gint           index,
		   gboolean       soft,
		   gboolean       hard)
{
	UrfArbitratorPrivate *priv = arbitrator->priv;
	UrfDevice *device;
	gboolean changed, old_hard = FALSE;
	char *object_path;

	g_return_if_fail (index >= 0);

	device = urf_arbitrator_find_device (arbitrator, index);
	if (device == NULL) {
		g_warning ("No device with index %u in the list", index);
		return;
	}

	old_hard = urf_device_is_hardware_blocked (device);

	changed = urf_device_update_states (device, soft, hard);

	if (changed == TRUE) {
		g_debug ("updating killswitch status %d to soft %d hard %d",
			 index, soft, hard);
		object_path = g_strdup (urf_device_get_object_path (device));
		g_signal_emit (G_OBJECT (arbitrator), signals[DEVICE_CHANGED], 0, object_path);
		g_free (object_path);

		if (priv->force_sync) {
			/* Sync soft and hard blocks */


			//  kernel-specific...
			if (hard == TRUE && soft == FALSE)
				urf_arbitrator_set_block_idx (arbitrator, index, TRUE);
			else if (hard != old_hard && hard == FALSE)
				urf_arbitrator_set_block_idx (arbitrator, index, FALSE);
		}
	}
}

/**
 * remove_killswitch:
 **/
static void
remove_killswitch (UrfArbitrator *arbitrator,
		   gint           index)
{
	UrfArbitratorPrivate *priv = arbitrator->priv;
	UrfDevice *device;
	gint type;
	const char *name;
	char *object_path = NULL;

	g_return_if_fail (index >= 0);

	device = urf_arbitrator_find_device (arbitrator, index);
	if (device == NULL) {
		g_warning ("No device with index %u in the list", index);
		return;
	}

	priv->devices = g_list_remove (priv->devices, device);
	type = urf_device_get_device_type (device);
	object_path = g_strdup (urf_device_get_object_path(device));

	name = urf_device_get_name (device);
	g_message ("removing killswitch idx %d %s", index, name);

	urf_killswitch_del_device (priv->killswitch[type], device);
	g_object_unref (device);

	g_signal_emit (G_OBJECT (arbitrator), signals[DEVICE_REMOVED], 0, object_path);
	g_free (object_path);
}

/**
 * add_killswitch:
 **/
static void
add_killswitch (UrfArbitrator *arbitrator,
		gint           index,
		gint           type,
		gboolean       soft,
		gboolean       hard)

{
	UrfDevice *device;

	g_return_if_fail (index >= 0);
	g_return_if_fail (type >= 0);

	device = urf_arbitrator_find_device (arbitrator, index);
	if (device != NULL) {
		g_warning ("device with index %u already in the list", index);
		return;
	}

	g_message ("adding killswitch idx %d soft %d hard %d", index, soft, hard);

	device = urf_device_kernel_new (index, type, soft, hard);

	urf_arbitrator_add_device (arbitrator, device);
}

static const char *
op_to_string (unsigned int op)
{
	switch (op) {
	case RFKILL_OP_ADD:
		return "ADD";
	case RFKILL_OP_DEL:
		return "DEL";
	case RFKILL_OP_CHANGE:
		return "CHANGE";
	case RFKILL_OP_CHANGE_ALL:
		return "CHANGE_ALL";
	default:
		g_assert_not_reached ();
	}
}

static void
print_event (struct rfkill_event *event)
{
	g_debug ("RFKILL event: idx %u type %u (%s) op %u (%s) soft %u hard %u",
		 event->idx,
		 event->type, type_to_string (event->type),
		 event->op, op_to_string (event->op),
		 event->soft, event->hard);
}

/**
 * event_cb:
 **/
static gboolean
event_cb (GIOChannel    *source,
	  GIOCondition   condition,
	  UrfArbitrator *arbitrator)
{
	if (condition & G_IO_IN) {
		GIOStatus status;
		struct rfkill_event event;
		gsize read;
		gboolean soft, hard;

		status = g_io_channel_read_chars (source,
						  (char *) &event,
						  sizeof(event),
						  &read,
						  NULL);

		while (status == G_IO_STATUS_NORMAL && read == sizeof(event)) {
			print_event (&event);

			soft = (event.soft > 0)?TRUE:FALSE;
			hard = (event.hard > 0)?TRUE:FALSE;

			if (event.op == RFKILL_OP_CHANGE) {
				update_killswitch (arbitrator, event.idx, soft, hard);
			} else if (event.op == RFKILL_OP_DEL) {
				remove_killswitch (arbitrator, event.idx);
			} else if (event.op == RFKILL_OP_ADD) {
				add_killswitch (arbitrator, event.idx, event.type, soft, hard);
			}

			status = g_io_channel_read_chars (source,
							  (char *) &event,
							  sizeof(event),
							  &read,
							  NULL);
		}
	} else {
		g_debug ("something else happened");
		return FALSE;
	}

	return TRUE;
}

/**
 * urf_arbitrator_startup
 **/
gboolean
urf_arbitrator_startup (UrfArbitrator *arbitrator,
			UrfConfig     *config)
{
	UrfArbitratorPrivate *priv = arbitrator->priv;
	struct rfkill_event event;
	int fd;
	//	int i;

	g_message ("%s",  __func__);

	priv->config = g_object_ref (config);
	priv->force_sync = urf_config_get_force_sync (config);
	priv->persist =	urf_config_get_persist (config);

	fd = open("/dev/rfkill", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		if (errno == EACCES)
			g_warning ("Could not open RFKILL control device, please verify your installation");
	} else {
		/* Disable rfkill input */
		ioctl(fd, RFKILL_IOCTL_NOINPUT);

		priv->fd = fd;

		while (1) {
			ssize_t len;

			len = read(fd, &event, sizeof(event));
			if (len < 0) {
				if (errno == EAGAIN)
					break;
				g_debug ("Reading of RFKILL events failed");
				break;
			}

			if (len != RFKILL_EVENT_SIZE_V1) {
				g_warning("Wrong size of RFKILL event\n");
				continue;
			}

			if (event.op != RFKILL_OP_ADD)
				continue;
			if (event.type >= NUM_RFKILL_TYPES)
				continue;

			add_killswitch (arbitrator, event.idx, event.type, event.soft, event.hard);
		}

		/* Setup monitoring */
		priv->channel = g_io_channel_unix_new (priv->fd);
		g_io_channel_set_encoding (priv->channel, NULL, NULL);
		priv->watch_id = g_io_add_watch (priv->channel,
		                                 G_IO_IN | G_IO_HUP | G_IO_ERR,
		                                 (GIOFunc) event_cb,
		                                 arbitrator);
	}

	// TODO: Need to fix this code, doesn't use GTask

	/* Set initial flight mode state from persistence */

	// AWE
	//
	// 1. is persist only used by us??
	//
	// 2. this code seems to run before the modem has been detected!!!
	if (priv->persist)
		urf_arbitrator_set_flight_mode (arbitrator,
						urf_config_get_persist_state (config, RFKILL_TYPE_ALL),
						NULL);


	// FIXME: doesn't this just duplicate code that flight_mode() performed already?
	//
	// set_flight_mode will call set_block for every device, and if the call succeeds, will
	// reset the persist_state of each!!!

	//	if (priv->persist) {
	//		/* Set all the devices that had saved state to what was saved */
	//		for (i = RFKILL_TYPE_ALL + 1; i < NUM_RFKILL_TYPES; i++) {

			// AWE: for now ignore callback for startup sequence...
	//			urf_arbitrator_set_block (arbitrator, i, urf_config_get_persist_state (config, i), NULL);
	//		}
	//	}

	return TRUE;
}

/**
 * urf_arbitrator_init:
 **/
static void
urf_arbitrator_init (UrfArbitrator *arbitrator)
{
	UrfArbitratorPrivate *priv = URF_ARBITRATOR_GET_PRIVATE (arbitrator);
	int i;

	arbitrator->priv = priv;
	priv->devices = NULL;
	priv->fd = -1;

	priv->killswitch[RFKILL_TYPE_ALL] = NULL;
	for (i = RFKILL_TYPE_ALL + 1; i < NUM_RFKILL_TYPES; i++)
		priv->killswitch[i] = urf_killswitch_new (i);
}

/**
 * urf_arbitrator_dispose:
 **/
static void
urf_arbitrator_dispose (GObject *object)
{
	UrfArbitratorPrivate *priv = URF_ARBITRATOR_GET_PRIVATE (object);
	int i;

	for (i = 0; i < NUM_RFKILL_TYPES; i++) {
		if (priv->killswitch[i]) {
			g_object_unref (priv->killswitch[i]);
			priv->killswitch[i] = NULL;
		}
	}

	if (priv->devices) {
		g_list_foreach (priv->devices, (GFunc) g_object_unref, NULL);
		g_list_free (priv->devices);
		priv->devices = NULL;
	}

	if (priv->config) {
		g_object_unref (priv->config);
		priv->config = NULL;
	}

	G_OBJECT_CLASS(urf_arbitrator_parent_class)->dispose(object);
}

/**
 * urf_arbitrator_finalize:
 **/
static void
urf_arbitrator_finalize (GObject *object)
{
	UrfArbitratorPrivate *priv = URF_ARBITRATOR_GET_PRIVATE (object);

	/* cleanup monitoring */
	if (priv->watch_id > 0) {
		g_source_remove (priv->watch_id);
		priv->watch_id = 0;
		g_io_channel_shutdown (priv->channel, FALSE, NULL);
		g_io_channel_unref (priv->channel);
	}
	close(priv->fd);

	G_OBJECT_CLASS(urf_arbitrator_parent_class)->finalize(object);
}

/**
 * urf_arbitrator_class_init:
 **/
static void
urf_arbitrator_class_init(UrfArbitratorClass *klass)
{
	GObjectClass *object_class = (GObjectClass *) klass;

	g_type_class_add_private(klass, sizeof(UrfArbitratorPrivate));
	object_class->dispose = urf_arbitrator_dispose;
	object_class->finalize = urf_arbitrator_finalize;

	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
			      G_TYPE_FROM_CLASS (klass),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (UrfArbitratorClass, device_added),
			      NULL, NULL,
			      g_cclosure_marshal_VOID__STRING,
			      G_TYPE_NONE, 1, G_TYPE_STRING);

	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
			      G_TYPE_FROM_CLASS (klass),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (UrfArbitratorClass, device_removed),
			      NULL, NULL,
			      g_cclosure_marshal_VOID__STRING,
			      G_TYPE_NONE, 1, G_TYPE_STRING);

	signals[DEVICE_CHANGED] =
		g_signal_new ("device-changed",
			      G_TYPE_FROM_CLASS (klass),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (UrfArbitratorClass, device_changed),
			      NULL, NULL,
			      g_cclosure_marshal_VOID__STRING,
			      G_TYPE_NONE, 1, G_TYPE_STRING);
}

/**
 * urf_arbitrator_new:
 **/
UrfArbitrator *
urf_arbitrator_new (void)
{
	UrfArbitrator *arbitrator;
	arbitrator = URF_ARBITRATOR(g_object_new (URF_TYPE_ARBITRATOR, NULL));
	return arbitrator;
}

