/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* RFC 9606, based on txt_16.c */

#ifndef RDATA_GENERIC_RESINFO_261_C
#define RDATA_GENERIC_RESINFO_261_C

static inline isc_result_t
generic_totext_resinfo(ARGS_TOTEXT) {
	isc_region_t region;

	UNUSED(tctx);

	dns_rdata_toregion(rdata, &region);

	while (region.length > 0) {
		RETERR(txt_totext(&region, 1, target));
		if (region.length > 0)
			RETERR(isc_str_tobuffer(" ", target));
	}

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
generic_fromwire_resinfo(ARGS_FROMWIRE) {
	isc_result_t result;

	UNUSED(type);
	UNUSED(dctx);
	UNUSED(rdclass);
	UNUSED(options);

	do {
		result = txt_fromwire(source, target);
		if (result != ISC_R_SUCCESS)
			return (result);
	} while (!buffer_empty(source));
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
totext_resinfo(ARGS_TOTEXT) {

	REQUIRE(rdata->type == dns_rdatatype_resinfo);

	return (generic_totext_resinfo(rdata, tctx, target));
}

static inline isc_result_t
fromwire_resinfo(ARGS_FROMWIRE) {

	REQUIRE(type == dns_rdatatype_resinfo);

	return (generic_fromwire_resinfo(rdclass, type, source, dctx, options,
				     target));
}

static inline isc_result_t
towire_resinfo(ARGS_TOWIRE) {

	REQUIRE(rdata->type == dns_rdatatype_resinfo);

	UNUSED(cctx);

	return (isc_mem_tobuffer(target, rdata->data, rdata->length));
}

#endif	/* RDATA_GENERIC_RESINFO_261_C */
