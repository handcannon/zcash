#pragma once

#include <vector>
#include <string>
#include <array>
#include <limits>
#include <assert.h>
#include <stdint.h>
#include "array_slice.hpp"

namespace libbitcoin {
namespace system {

#define BC_API
#define BC_CONSTEXPR constexpr
#define BITCOIN_ASSERT(expression) assert(expression)

#define BC_LOCALE_BACKEND "icu"
#define BC_LOCALE_UTF8 "en_US.UTF8"

typedef std::vector<std::string> string_list;

static constexpr size_t hash_size = 32;
static constexpr size_t long_hash_size = 2 * hash_size;

// Define a byte array of a specified length.
template <size_t Size>
using byte_array = std::array<uint8_t, Size>;
typedef byte_array<long_hash_size> long_hash;
typedef byte_array<hash_size> hash_digest;

typedef std::vector<uint8_t> data_chunk;
typedef array_slice<uint8_t> data_slice;

//#define MAX_INT32 std::numeric_limits<int32_t>::max()
BC_CONSTEXPR int32_t max_int32 = std::numeric_limits<int32_t>::max();


template <typename Element, typename Container>
int find_position(const Container& list, const Element& value)
{
	const auto it = std::find(std::begin(list), std::end(list), value);

	if (it == std::end(list))
		return -1;

	// Unsafe for use with lists greater than max_int32 in size.
	BITCOIN_ASSERT(list.size() <= max_int32);
	return static_cast<int>(std::distance(list.begin(), it));
}

/// Generate a sha256 hash.
BC_API hash_digest sha256_hash(const data_slice& data);

/// Generate a pkcs5 pbkdf2 hmac sha512 hash.
BC_API long_hash pkcs5_pbkdf2_hmac_sha512(const data_slice& passphrase,
	const data_slice& salt, size_t iterations);

/**
 * Join a list of strings into a single string, in order.
 * @param[in]  words      The list of strings to join.
 * @param[in]  delimiter  The delimiter, defaults to " ".
 * @return                The resulting string.
 */
BC_API std::string join(const string_list& words,
	const std::string& delimiter = " ");

/**
 * Normalize a string value using nfkd normalization.
 * Failure is indicated by empty string return for non-empty value.
 * This function requires the ICU dependency.
 * @param[in]  value  The value to normalize.
 * @return            The normalized value.
 */
BC_API std::string to_normal_nfkd_form(const std::string& value);

} // namespace system
} // namespace libbitcoin
