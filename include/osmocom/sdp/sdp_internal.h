/* Internal header for non-public API shared across .c files */
#pragma once

struct token {
	const char *start;
	const char *end;
};

/* Copy a string from [start,end[, return as talloc allocated under ctx in *dst.
 * If *dst is non-NULL, talloc_free(*dst) first. */
void token_copy(void *ctx, char **dst, const struct token *t);
