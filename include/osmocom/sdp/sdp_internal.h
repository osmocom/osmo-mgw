/* Internal header for non-public API shared across .c files */
#pragma once

struct token {
	const char *start;
	const char *end;
};

/* Copy a string from [start,end[, return as talloc allocated under ctx in *dst.
 * If *dst is non-NULL, talloc_free(*dst) first. */
void token_copy(void *ctx, char **dst, const struct token *t);

const char *token_chr(const struct token *src, char c);
const char *token_chrs(const struct token *src, const char *chrs);
void token_next(struct token *t, const char *str, const char *end, const char *separators);

const char *token_to_int64(int64_t *result, const struct token *t, int base, int min_val, int max_val);
const char *token_to_int(int *result, const struct token *t, int base, int min_val, int max_val);
