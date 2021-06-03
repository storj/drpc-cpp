// Copyright (c) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

#include <algorithm>
#include <bit>
#include <cassert>
#include <cstddef>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include <drpc/wire.h>

namespace drpc {

void bytevec::push_back(char c) {
	std::vector<byte>::push_back(static_cast<byte>(c));
}

// helper for appending std::string byte sequences, since char isn't
// directly assignable to byte
bytevec::iterator bytevec::concat(const std::string& s) {
	auto s_as_bytes = reinterpret_cast<const byte*>(s.data());
	return insert(end(), s_as_bytes, s_as_bytes + s.size());
}

bytevec::iterator bytevec::concat(const bytevec& other) {
	return insert(end(), other.begin(), other.end());
}

[[nodiscard]] bytevec bytevec::subrange(size_type n, size_type length) const {
	if (length == 0) {
		return bytevec {};
	}
	size_type sz = size();
	if (n >= sz) {
		throw std::out_of_range("bytevec subrange start point out of range");
	}
	auto start_iter = data() + n;
	auto maxlength = sz - n;
	if (length == npos) {
		length = maxlength;
	} else if (length > maxlength) { // avoids wraparound
		throw std::out_of_range("bytevec subrange length out of range");
	}
	return bytevec(start_iter, start_iter + length);
}

[[nodiscard]] std::string bytevec::as_string() const {
	auto start_iter = reinterpret_cast<const char*>(data());
	return std::string {start_iter, start_iter + size()};
}

namespace wire {

frame_iterator split_into_frames(const Packet& pkt, int n) {
	if (n == 0) {
		n = 64 * 1024;
	} else if (n < 0) {
		n = 0;
	}
	return frame_iterator(pkt, n);
}

void varint_encode(bytevec& buf, std::uint64_t n) {
	while (n >= 0x80) {
		buf.push_back(byte((n & 0x7f) | 0x80));
		n >>= 7;
	}
	buf.push_back(byte(n & 0x7f));
}

// This would be way simpler as a simple call to std::bit_width, but it's not
// available on apple's libc++ yet. They have std::log2p1 instead, which is the
// same thing, but I can't find a way with dumb template tricks to select one of
// those based on what's present in std::. At least everybody seems to have
// std::countl_zero.
static inline std::uint64_t bit_width(std::uint64_t n) noexcept {
	return n == 0 ? 0 : 64 - std::countl_zero(n);
}

std::uint64_t varint_size(std::uint64_t n) {
	return 9 * bit_width(n) / 64 + 1;
}

std::uint64_t encoded_string_size(const std::string& s) {
	return 1 + varint_size(s.size()) + std::uint64_t(s.size());
}

void encode_metadata(bytevec& buf, const std::map<std::string, std::string>& md) {
	for (auto& [key, value] : md) {
		buf.push_back(10); // 1<<3 | 2
		varint_encode(buf, encoded_string_size(key) + encoded_string_size(value));
		buf.push_back(10); // 1<<3 | 2
		varint_encode(buf, key.size());
		buf.concat(key);
		buf.push_back(18); // 2<<3 | 2
		varint_encode(buf, value.size());
		buf.concat(value);
	}
}

// Seriously, SHEESH. Get it together, standards bodies.
#if defined(__linux__)
#  ifndef _DEFAULT_SOURCE
#    define _DEFAULT_SOURCE
#  endif
#  include <endian.h>
#  define betoh64(n) (::be64toh(n))
#elif defined(__APPLE__)
#  include <libkern/OSByteOrder.h>
#  define betoh64(n) (OSSwapBigToHostInt64(n))
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#  include <sys/endian.h>
#  define betoh64(n) (::be64toh(n))
#elif defined(__OpenBSD__)
#  include <sys/endian.h>
#  define betoh64(n) (::betoh64(n))
#elif defined(_WIN32) || defined(_WIN64) || defined(__WINDOWS__)
#  include <windows.h>
#  if BYTE_ORDER == LITTLE_ENDIAN
#    if defined(_MSC_VER)
#      include <stdlib.h>
#      define betoh64(n) (_byteswap_uint64(n))
#    elif defined(__GNUC__) || defined(__clang__)
#      define betoh64(n) (__builtin_bswap64(n))
#    endif
#  elif BYTE_ORDER == BIG_ENDIAN
#    define betoh64(n) (n)
#  else
#    error byte order not supported
#  endif
#endif

ErrorWithCode decode_error(const bytevec& encoded) {
	if (encoded.size() < sizeof(std::uint64_t)) {
		return ErrorWithCode(0, encoded.as_string() + " (drpc note: invalid error data)");
	}
	auto code = betoh64(*reinterpret_cast<const std::uint64_t*>(encoded.data()));
	return ErrorWithCode(code, encoded.subrange(sizeof(std::uint64_t)).as_string());
}

void encode_frame(bytevec& buf, const wire::Frame& fr) {
	byte control = static_cast<byte>(fr.kind) << 1;
	if (fr.done) {
		control |= byte(0x01);
	}
	if (fr.control) {
		control |= byte(0x80);
	}
	buf.push_back(control);
	varint_encode(buf, fr.id.stream);
	varint_encode(buf, fr.id.message);
	varint_encode(buf, fr.data.size());
	buf.concat(fr.data);
}

bool BytevecOutputStream::Next(void** data, int* size) {
	size_t old_size = target_p->size();

	// Grow the string.
	size_t new_size;
	if (old_size < target_p->capacity()) {
		// Resize the string to match its capacity, since we can get away
		// without a memory allocation this way.
		new_size = target_p->capacity();
	} else {
		// Size has reached capacity, try to double it.
		new_size = old_size * 2;
	}
	// Avoid integer overflow in returned '*size'.
	new_size = std::min(new_size, old_size + std::numeric_limits<int>::max());
	// Increase the size, also make sure that it is at least kMinimumSize.
	target_p->resize(std::max(new_size, kMinimumSize));

	*data = reinterpret_cast<void*>(target_p->data() + old_size);
	*size = static_cast<int>(target_p->size() - old_size);
	return true;
}

void BytevecOutputStream::BackUp(int count) {
	assert(count > 0);
	assert(target_p != nullptr);
	assert(static_cast<std::size_t>(count) < target_p->size());
	target_p->resize(target_p->size() - static_cast<std::size_t>(count));
}

[[nodiscard]] std::int64_t BytevecOutputStream::ByteCount() const {
	assert(target_p != nullptr);
	return static_cast<std::int64_t>(target_p->size());
}

} // namespace wire

} // namespace drpc
