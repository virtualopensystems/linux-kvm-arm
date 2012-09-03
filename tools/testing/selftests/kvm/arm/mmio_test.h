#ifndef MMIO_TEST_H
#define MMIO_TEST_H

#define IO_DATA_BASE (0xc0000000)
#define IO_DATA \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI" \
	"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzi" \
	"The quick brown fox jumps over the lazy dog1234567890ABCDEFGHI"

#endif /* MMIO_TEST_H */
