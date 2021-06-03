// Copyright (c) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

#ifndef DRPC_CPP_WIRE_H
#define DRPC_CPP_WIRE_H

#include <cstddef>
#include <iterator>
#include <exception>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/message.h>

namespace drpc {

using byte = std::byte;

class bytevec : public std::vector<byte> {
public:
	using std::vector<byte>::vector;

	explicit bytevec(const std::string& s)
		: bytevec(
			reinterpret_cast<const byte*>(s.data()),
			reinterpret_cast<const byte*>(s.data()) + s.size()
		)
	{}

	using std::vector<byte>::size_type;
	using std::vector<byte>::push_back;

	// helper for appending bytes in char form, since char isn't
	// directly assignable to byte
	void push_back(char c);

	// helper for appending std::string byte sequences, since char isn't
	// directly assignable to byte
	iterator concat(const std::string& s);

	iterator concat(const bytevec& other);

	static const size_type npos = -1;

	[[nodiscard]] bytevec subrange(size_type n, size_type length = npos) const;

	[[nodiscard]] std::string as_string() const;

	[[nodiscard]] std::string_view view() {
		return std::string_view(reinterpret_cast<const char*>(data()), size());
	}
};

namespace wire {

enum Kind : std::uint8_t {
	Invoke = 1,
	Message = 2,
	Error = 3,
	Close = 5,
	CloseSend = 6,
	InvokeMetadata = 7
};

struct ID {
	std::uint64_t stream;
	std::uint64_t message;

	friend bool operator<(ID a, ID b) {
		return a.stream < b.stream || (a.stream == b.stream && a.message < b.message);
	}
};

struct Packet {
	Packet(ID id, Kind kind, bytevec data)
		: id {id}
		, kind {kind}
		, data {std::move(data)}
	{}

	Packet()
		: Packet(ID{}, Kind(0), bytevec{})
	{}

	ID id;
	Kind kind;
	bytevec data;
};

struct Frame {
	Frame(ID id, Kind kind)
		: id {id}
		, kind {kind}
		, data {}
		, done {false}
		, control {false}
	{}

	Frame()
		: Frame(ID{}, Kind(0))
	{}

	ID id;
	Kind kind;
	bytevec data;
	bool done;
	bool control;
};

class frame_iterator_end {};

class frame_iterator {
public:
	using iterator_category = std::input_iterator_tag;
	using value_type = Frame;
	using difference_type = int;

	frame_iterator()
	: frame {}
	, n {0}
	, pkt_data {}
	, past_the_end {true}
	{}

	frame_iterator(const frame_iterator&) = default;
	frame_iterator(frame_iterator&&) = default;
	frame_iterator& operator=(const frame_iterator&) = default;
	frame_iterator& operator=(frame_iterator&&) = default;

	frame_iterator(const Packet& pkt, int n)
	: frame_iterator {pkt.id, pkt.kind, n, pkt.data}
	{}

	bool operator!=(const frame_iterator_end&) const noexcept {
		return !past_the_end;
	}

	const Frame& operator*() const noexcept {
		return frame;
	}

	frame_iterator& operator++() noexcept {
		advance_frame();
		return *this;
	}

	frame_iterator operator++(int) noexcept {
		frame_iterator tmp {*this};
		advance_frame();
		return tmp;
	}

	frame_iterator& begin() noexcept { return *this; }
	static frame_iterator_end end() noexcept { return frame_iterator_end{}; }

private:
	frame_iterator(wire::ID id, wire::Kind kind, int n, bytevec pkt_data)
		: frame {id, kind}
		, n {n}
		, pkt_data {std::move(pkt_data)}
		, past_the_end {false}
	{
		// only want to do this for new instances, not copies
		advance_frame();
	}

	void advance_frame() noexcept {
		if (frame.done) {
			// we've already yielded the end-of-packet frame
			frame.data.clear();
			past_the_end = true;
		} else if (n > 0 && pkt_data.size() > static_cast<std::size_t>(n)) {
			// everything we need to send won't fit in one frame
			frame.data = pkt_data.subrange(0, n);
			pkt_data = pkt_data.subrange(n);
			frame.done = false;
		} else {
			// everything fits in one frame; this is the last one
			frame.data = pkt_data;
			pkt_data.clear();
			frame.done = true;
		}
	}

	Frame frame;
	int n;
	bytevec pkt_data;
	bool past_the_end;
};

frame_iterator split_into_frames(const Packet& pkt, int n);

class ErrorWithCode : public std::exception {
public:
	ErrorWithCode(std::uint64_t code, const std::string& message)
		: std::exception {}
		, code {code}
	{
		std::stringstream ss;
		ss << "[DRPC code=" << code << "] " << message;
		what_str = ss.str();
	}

	[[nodiscard]] const char* what() const noexcept override {
		return what_str.c_str();
	}

	std::uint64_t code;
	std::string what_str;
};

void varint_encode(bytevec& buf, std::uint64_t n);

std::uint64_t varint_size(std::uint64_t n);

std::uint64_t encoded_string_size(const std::string& s);

void encode_metadata(bytevec& buf, const std::map<std::string, std::string>& md);

ErrorWithCode decode_error(const bytevec& encoded);

void encode_frame(bytevec& buf, const wire::Frame& fr);

// A ZeroCopyOutputStream which appends bytes to a bytevec.
//
// Based nearly entirely on google::protobuf::io::StringOutputStream.
class BytevecOutputStream : public ::google::protobuf::io::ZeroCopyOutputStream {
public:
	// Create a BytevecOutputStream which appends bytes to the given bytevec.
	// The bytevec remains property of the caller, but it is mutated in arbitrary
	// ways and MUST NOT be accessed in any way until you're done with the
	// stream. Either be sure there's no further usage, or (safest) destroy the
	// stream before using the contents.
	//
	// Hint:  If you call target->reserve(n) before creating the stream,
	//   the first call to Next() will return at least n bytes of buffer
	//   space.
	explicit BytevecOutputStream(bytevec& target)
		: target_p {&target}
	{}

	~BytevecOutputStream() override = default;

	BytevecOutputStream(const BytevecOutputStream& rhs) = delete;
	BytevecOutputStream& operator=(const BytevecOutputStream& rhs) = delete;
	BytevecOutputStream(BytevecOutputStream&& rhs) = delete;
	BytevecOutputStream& operator=(BytevecOutputStream&& rhs) = delete;

	// implements ZeroCopyOutputStream ---------------------------------
	bool Next(void** data, int* size) override;
	void BackUp(int count) override;
	[[nodiscard]] std::int64_t ByteCount() const override;

private:
	static constexpr size_t kMinimumSize = 16;

	bytevec* target_p;
};

class BytevecInputStream : public ::google::protobuf::io::ArrayInputStream {
public:
	explicit BytevecInputStream(const bytevec& target)
		: ::google::protobuf::io::ArrayInputStream(target.data(), static_cast<int>(target.size()))
	{}

	~BytevecInputStream() override = default;
};

template <typename M, typename = void>
class Encoding {};

template <typename M>
bool encode_message(const M& m, bytevec& buf) {
	return Encoding<M>::encode(m, buf);
}

template <typename M>
bool decode_message(M& m, const bytevec& buf) {
	return Encoding<M>::decode(m, buf);
}

template <typename MessageType>
class Encoding<MessageType, std::enable_if_t<std::is_base_of_v<::google::protobuf::Message, MessageType>>> {
public:
	static bool encode(const MessageType& m, bytevec& buf) {
		BytevecOutputStream b(buf);
		return m.SerializeToZeroCopyStream(&b);
	}

	static bool decode(MessageType& m, const bytevec& buf) {
		BytevecInputStream b(buf);
		return m.ParseFromZeroCopyStream(&b);
	}
};

} // namespace wire

} // namespace drpc

#endif //DRPC_CPP_WIRE_H
