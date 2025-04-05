/*
**
** This file is part of Bevara Access Filters.
**
** This file is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation.
**
** This file is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License along with this file. If not, see <https://www.gnu.org/licenses/>.
*/

#include <gpac/filters.h>
#include <gpac/avparse.h>

typedef struct
{
	// options
	GF_Fraction fps;

	// only one input pid declared
	GF_FilterPid *ipid;
	// only one output pid declared
	GF_FilterPid *opid;
	u32 src_timescale;
	Bool is_bmp;
	Bool owns_timescale;
	u32 codec_id;

	Bool initial_play_done;
	Bool is_playing;
} GF_ReframeJpegCtx;

static GF_Err jpeg_configure_pid(GF_Filter *filter, GF_FilterPid *pid, Bool is_remove)
{
	GF_ReframeJpegCtx *ctx = gf_filter_get_udta(filter);
	const GF_PropertyValue *p;

	if (is_remove)
	{
		ctx->ipid = NULL;
		return GF_OK;
	}

	if (!gf_filter_pid_check_caps(pid))
		return GF_NOT_SUPPORTED;

	gf_filter_pid_set_framing_mode(pid, GF_TRUE);
	ctx->ipid = pid;
	// force retest of codecid
	ctx->codec_id = 0;

	p = gf_filter_pid_get_property(pid, GF_PROP_PID_TIMESCALE);
	if (p)
		ctx->src_timescale = p->value.uint;

	if (ctx->src_timescale && !ctx->opid)
	{
		ctx->opid = gf_filter_pid_new(filter);
		gf_filter_pid_copy_properties(ctx->opid, ctx->ipid);
		gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_UNFRAMED, NULL);
	}
	ctx->is_playing = GF_TRUE;
	return GF_OK;
}

static Bool jpeg_process_event(GF_Filter *filter, const GF_FilterEvent *evt)
{
	GF_FilterEvent fevt;
	GF_ReframeJpegCtx *ctx = gf_filter_get_udta(filter);
	if (evt->base.on_pid != ctx->opid)
		return GF_TRUE;
	switch (evt->base.type)
	{
	case GF_FEVT_PLAY:
		if (ctx->is_playing)
		{
			return GF_TRUE;
		}

		ctx->is_playing = GF_TRUE;
		if (!ctx->initial_play_done)
		{
			ctx->initial_play_done = GF_TRUE;
			return GF_TRUE;
		}

		GF_FEVT_INIT(fevt, GF_FEVT_SOURCE_SEEK, ctx->ipid);
		fevt.seek.start_offset = 0;
		gf_filter_pid_send_event(ctx->ipid, &fevt);
		return GF_TRUE;
	case GF_FEVT_STOP:
		ctx->is_playing = GF_FALSE;
		return GF_FALSE;
	default:
		break;
	}
	// cancel all events
	return GF_TRUE;
}

static GF_Err jpeg_process(GF_Filter *filter)
{
	GF_ReframeJpegCtx *ctx = gf_filter_get_udta(filter);
	GF_FilterPacket *pck, *dst_pck;
	GF_Err e;
	u8 *data, *output;
	u32 size, w = 0, h = 0, pf = 0;
	u8 *pix;
	u32 i, j, irow, in_stride, out_stride;
	GF_BitStream *bs;

	pck = gf_filter_pid_get_packet(ctx->ipid);
	if (!pck)
	{
		if (gf_filter_pid_is_eos(ctx->ipid))
		{
			if (ctx->opid)
				gf_filter_pid_set_eos(ctx->opid);
			ctx->is_playing = GF_FALSE;
			return GF_EOS;
		}
		return GF_OK;
	}
	data = (u8 *)gf_filter_pck_get_data(pck, &size);

	if (!ctx->opid || !ctx->codec_id)
	{
		u32 dsi_size;
		u8 *dsi = NULL;
		const char *ext, *mime;
		const GF_PropertyValue *prop;
		u32 codecid = 0;

		bs = gf_bs_new(data, size, GF_BITSTREAM_READ);
		gf_img_parse(bs, &codecid, &w, &h, &dsi, &dsi_size);
		gf_bs_del(bs);

		prop = gf_filter_pid_get_property(ctx->ipid, GF_PROP_PID_FILE_EXT);
		ext = (prop && prop->value.string) ? prop->value.string : "";
		prop = gf_filter_pid_get_property(ctx->ipid, GF_PROP_PID_MIME);
		mime = (prop && prop->value.string) ? prop->value.string : "";

		if (!codecid)
		{
			if (!stricmp(ext, "jpeg") || !stricmp(ext, "jpg") || !strcmp(mime, "image/jpg"))
			{
				codecid = GF_CODECID_JPEG;
			}
		}
		if (!codecid)
		{
			gf_filter_pid_drop_packet(ctx->ipid);
			return GF_NOT_SUPPORTED;
		}
		ctx->codec_id = codecid;
		ctx->opid = gf_filter_pid_new(filter);
		if (!ctx->opid)
		{
			gf_filter_pid_drop_packet(ctx->ipid);
			return GF_SERVICE_ERROR;
		}
		if (!ctx->fps.num || !ctx->fps.den)
		{
			ctx->fps.num = 1000;
			ctx->fps.den = 1000;
		}
		// we don't have input reconfig for now
		gf_filter_pid_copy_properties(ctx->opid, ctx->ipid);
		gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_STREAM_TYPE, &PROP_UINT(GF_STREAM_VISUAL));
		gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_CODECID, &PROP_UINT(codecid));
		if (pf)
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_PIXFMT, &PROP_UINT(pf));
		if (w)
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_WIDTH, &PROP_UINT(w));
		if (h)
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_HEIGHT, &PROP_UINT(h));
		if (dsi)
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_DECODER_CONFIG, &PROP_DATA_NO_COPY(dsi, dsi_size));

		if (!gf_filter_pid_get_property(ctx->ipid, GF_PROP_PID_TIMESCALE))
		{
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_TIMESCALE, &PROP_UINT(ctx->fps.num));
			ctx->owns_timescale = GF_TRUE;
		}

		gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_NB_FRAMES, &PROP_UINT(1));
		gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_PLAYBACK_MODE, &PROP_UINT(GF_PLAYBACK_MODE_FASTFORWARD));

		if (ext || mime)
			gf_filter_pid_set_property(ctx->opid, GF_PROP_PID_CAN_DATAREF, &PROP_BOOL(GF_TRUE));
	}
	e = GF_OK;
	u32 start_offset = 0;

	dst_pck = gf_filter_pck_new_ref(ctx->opid, start_offset, size - start_offset, pck);
	if (!dst_pck)
		return GF_OUT_OF_MEM;

	gf_filter_pck_merge_properties(pck, dst_pck);
	if (ctx->owns_timescale)
	{
		gf_filter_pck_set_cts(dst_pck, 0);
		gf_filter_pck_set_sap(dst_pck, GF_FILTER_SAP_1);
		gf_filter_pck_set_duration(dst_pck, ctx->fps.den);
	}
	gf_filter_pck_send(dst_pck);
	gf_filter_pid_drop_packet(ctx->ipid);
	return e;

	return e;
}

#include <gpac/internal/isomedia_dev.h>

static const char *jpeg_probe_data(const u8 *data, u32 size, GF_FilterProbeScore *score)
{
	/*JPEG*/
	if ((data[0] == 0xFF) && (data[1] == 0xD8) && (data[2] == 0xFF))
	{
		*score = GF_FPROBE_SUPPORTED;
		return "image/jpg";
	}

	return NULL;
}

static const GF_FilterCapability ReframeImgCaps[] =
	{
		CAP_UINT(GF_CAPS_INPUT, GF_PROP_PID_STREAM_TYPE, GF_STREAM_FILE),
		CAP_STRING(GF_CAPS_INPUT, GF_PROP_PID_FILE_EXT, "jpg|jpeg"),
		CAP_STRING(GF_CAPS_INPUT, GF_PROP_PID_MIME, "image/jpg"),
		CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_STREAM_TYPE, GF_STREAM_VISUAL),
		CAP_UINT(GF_CAPS_OUTPUT, GF_PROP_PID_CODECID, GF_CODECID_JPEG)
};

#define OFFS(_n) #_n, offsetof(GF_ReframeJpegCtx, _n)
static const GF_FilterArgs ReframeJpegArgs[] =
	{
		{OFFS(fps), "import frame rate (0 default to 1 Hz)", GF_PROP_FRACTION, "0/1000", NULL, GF_FS_ARG_HINT_HIDE},
		{0}};

GF_FilterRegister ReframeJpegRegister = {
	.name = "rfjpeg",
	GF_FS_SET_DESCRIPTION("JPG reframer")
		GF_FS_SET_HELP("This filter parses JPG files/data and outputs corresponding visual PID and frames.\n")
			.private_size = sizeof(GF_ReframeJpegCtx),
	.args = ReframeJpegArgs,
	SETCAPS(ReframeImgCaps),
	.configure_pid = jpeg_configure_pid,
	.probe_data = jpeg_probe_data,
	.process = jpeg_process,
	.process_event = jpeg_process_event};

const GF_FilterRegister * EMSCRIPTEN_KEEPALIVE dynCall_jpegdec_reframe_register(GF_FilterSession *session)
{
	return &ReframeJpegRegister;
}
