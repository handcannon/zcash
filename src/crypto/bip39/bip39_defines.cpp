#include <mutex>
#include <boost/algorithm/string.hpp>
#include <boost/locale/generator.hpp>
#include <boost/locale/conversion.hpp>
#include <boost/locale/localization_backend.hpp>
#include "bip39_defines.h"
#include "math/sha256.h"
#include "math/pkcs5_pbkdf2.h"

namespace libbitcoin {
namespace system {

hash_digest sha256_hash(const data_slice& data)
{
	hash_digest hash;
	SHA256_(data.data(), data.size(), hash.data());
	return hash;
}

long_hash pkcs5_pbkdf2_hmac_sha512(const data_slice& passphrase,
	const data_slice& salt, size_t iterations)
{
	long_hash hash;
	const auto result = pkcs5_pbkdf2(passphrase.data(), passphrase.size(),
		salt.data(), salt.size(), hash.data(), hash.size(), iterations);

	if (result != 0)
		throw std::bad_alloc();

	return hash;
}

std::string join(const string_list& words, const std::string& delimiter)
{
	return boost::join(words, delimiter);
}

using namespace boost::locale;

inline char ascii_to_lowercase(char character)
{
	return character + ('a' - 'A');
}

// Normalize and validate input characters.
static bool normalize(data_chunk& out, const std::string& in)
{
	out.clear();
	out.reserve(in.length());
	auto uppercase = false;
	auto lowercase = false;

	for (auto character : in)
	{
		if (character >= 'A' && character <= 'Z')
		{
			uppercase = true;
			character = ascii_to_lowercase(character);
		}
		else if (character >= 'a' && character <= 'z')
		{
			lowercase = true;
		}
		else if (character < '!' || character > '~')
		{
			return false;
		}

		out.push_back(static_cast<uint8_t>(character));
	}

	// Must not accept mixed case strings.
	return !(uppercase && lowercase);
}

// The backend selection is ignored if invalid (in this case on Windows).
static std::string normal_form(const std::string& value, norm_type form)
{
	if (value.empty())
		return value;

	/*
#ifdef _MSC_VER
	// Workaround lack of ICU support in published boost-locale NuGet packages.
	const auto norm = to_win32_normal_form(form);
	const auto wide_value = to_utf16(value);
	const auto source = wide_value.c_str();
	const auto full_size = wide_value.size();

	// The input length exceeds the maximum convertible size.
	if (full_size > max_int32)
		return {};

	const auto size = static_cast<uint32_t>(full_size);
	const auto estimate = NormalizeString(norm, source, size, NULL, 0);

	if (estimate <= 0)
		return {};

	auto buffer = std::wstring(estimate, {});
	const auto length = NormalizeString(norm, source, size, &buffer.front(),
		estimate);

	if (length <= 0)
		return {};

	return to_utf8(buffer.substr(0, length));
#else
	auto backend_manager = localization_backend_manager::global();
	backend_manager.select(BC_LOCALE_BACKEND);
	const generator locale(backend_manager);
	return normalize(value, form, locale(BC_LOCALE_UTF8));
#endif */

	auto backend_manager = localization_backend_manager::global();
	backend_manager.select(BC_LOCALE_BACKEND);
	const generator locale(backend_manager);
	return normalize(value, form, locale(BC_LOCALE_UTF8));
}

// Ensure validate_localization is called only once.
static std::once_flag icu_mutex;

// One time verifier of the localization backend manager. This is
// necessary because boost::normalize will fail silently to perform
// normalization if the ICU dependency is missing.
static void validate_localization()
{
#ifndef _MSC_VER
	const auto backend_manager = localization_backend_manager::global();
	const auto available_backends = backend_manager.get_all_backends();
	const auto iterator = std::find(available_backends.cbegin(),
		available_backends.cend(), BC_LOCALE_BACKEND);

	if (iterator == available_backends.cend())
		throw std::runtime_error(
			"Unicode normalization test failed, a dependency may be missing.");
#endif
}

// Normalize strings using unicode nfkd normalization.
std::string to_normal_nfkd_form(const std::string& value)
{
	std::call_once(icu_mutex, validate_localization);
	return normal_form(value, norm_type::norm_nfkd);
}

} // namespace system
} // namespace libbitcoin
