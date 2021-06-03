// Copyright (c) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

#ifndef DRPC_CPP_STREAM_H
#define DRPC_CPP_STREAM_H

#include <exception>
#include <ios>
#include <string>
#include <vector>

#include <drpc/wire.h>
#include <drpc/concepts.h>

namespace drpc {

class SerializationError : public std::runtime_error {
public:
	using std::runtime_error::runtime_error;
};

class EndOfStream : public std::ios_base::failure {
public:
	EndOfStream()
		: std::ios_base::failure {"EOF"} {
	}
};

class ProtocolError : public std::runtime_error {
public:
	using std::runtime_error::runtime_error;
};

class StreamClosedByPeer : public ProtocolError {
public:
	StreamClosedByPeer()
		: ProtocolError("stream closed by peer") {
	}
};

template <Transport TransportT>
class RPCStreamBase {
public:
	using TransportType = TransportT;

	// Caller must keep the transport in scope until this RPCStream is done.
	RPCStreamBase(TransportType& t, std::uint64_t sid)
		: transport {t}
		, local_id {.stream = sid, .message = 0}
		, remote_id {.stream = 0, .message = 0}
		, split_size {0}
	{}

	wire::Packet new_packet(wire::Kind kind, bytevec bytes) {
		++local_id.message;
		return {local_id, kind, std::move(bytes)};
	}

protected:
	TransportType& transport;
	wire::ID local_id;
	wire::ID remote_id;
	int split_size;
};

template <Transport TransportT>
class AsyncRPCStream : public RPCStreamBase<TransportT> {
public:
	using RPCStreamBase<TransportT>::RPCStreamBase;

	asio::awaitable<void> async_send_packet(wire::Kind kind, bytevec bytes) {
		auto frames = wire::split_into_frames(this->new_packet(kind, std::move(bytes)), this->split_size);
		for (auto& fr : frames) {
			bytevec buf;
			wire::encode_frame(buf, fr);
			co_await asio::async_write(this->transport, asio::buffer(buf), asio::use_awaitable);
		}
	}

	asio::awaitable<byte> async_read_byte() {
		byte buf[1];
		auto count = co_await asio::async_read(this->transport, asio::buffer(buf), asio::use_awaitable);
		if (count < 1) {
			throw EndOfStream();
		}
		co_return buf[0];
	}

	asio::awaitable<std::uint64_t> async_read_varint() {
		std::uint64_t out {0};
		for (uint shift = 0; shift < 64; shift += 7) {
			auto val = co_await async_read_byte();
			out |= (static_cast<std::uint64_t>(val & byte(0x7f)) << shift);
			if (val < byte(0x80)) {
				co_return out;
			}
		}
		throw ProtocolError("varint too long");
	}

	asio::awaitable<wire::Frame> async_receive_frame() {
		wire::Frame frame;
		auto control = co_await async_read_byte();
		frame.done = (control & byte(0x01)) != byte(0);
		frame.control = (control & byte(0x80)) != byte(0);
		frame.kind = static_cast<wire::Kind>((control & byte(0x7e)) >> 1);
		frame.id.stream = co_await async_read_varint();
		frame.id.message = co_await async_read_varint();
		auto frame_length = co_await async_read_varint();
		frame.data = bytevec(frame_length, byte(0));
		auto count = co_await asio::async_read(this->transport, asio::buffer(frame.data), asio::use_awaitable);
		if (count < frame_length) {
			throw EndOfStream();
		}
		co_return frame;
	}

	asio::awaitable<wire::Packet> async_receive_packet() {
		wire::Packet pkt;
		bytevec buf;
		while (true) {
			auto frame = co_await async_receive_frame();
			if (frame.control) {
				// Ignore any frames with the control bit set so that we can
				// use it in the future to mean things to people who understand
				// it.
				continue;
			}
			if (frame.id < this->remote_id) {
				throw ProtocolError("id monotonicity violation");
			}
			if (this->remote_id < frame.id) {
				// When a new ID is read, the old data is discarded. This allows
				// for easier asynchronous interrupts.
				this->remote_id = frame.id;
				buf.clear();
				pkt.id = frame.id;
				pkt.kind = frame.kind;
			} else if (frame.kind != pkt.kind) {
				throw ProtocolError("packet kind change");
			}
			buf.concat(frame.data);
			if (buf.size() > (4 << 20)) {
				throw ProtocolError("data overflow");
			}
			if (frame.done) {
				pkt.data = std::move(buf);
				co_return pkt;
			}
		}
	}

	asio::awaitable<bytevec> async_receive_message() {
		while (true) {
			auto packet = co_await async_receive_packet();
			switch (packet.kind) {
			case wire::Kind::Invoke:
				throw ProtocolError("invoke on existing stream");
			case wire::Kind::Message:
				co_return std::move(packet.data);
			case wire::Kind::Error:
				throw wire::decode_error(packet.data);
			case wire::Kind::Close:
				throw StreamClosedByPeer();
			case wire::Kind::CloseSend:
				// set eof on receive
			default:
				throw ProtocolError(
					std::string("unknown packet kind: ")
					+ std::to_string(static_cast<int>(packet.kind))
				);
			}
		}
	}
};

template <Transport TransportT>
class RPCStream : public RPCStreamBase<TransportT> {
public:
	using RPCStreamBase<TransportT>::RPCStreamBase;

	void send_packet(wire::Kind kind, bytevec bytes) {
		auto frames = wire::split_into_frames(this->new_packet(kind, std::move(bytes)), this->split_size);
		for (auto& fr : frames) {
			bytevec buf;
			wire::encode_frame(buf, fr);
			asio::write(this->transport, asio::buffer(buf));
		}
	}

	byte read_byte() {
		byte buf[1];
		auto count = asio::read(this->transport, asio::buffer(buf));
		if (count < 1) {
			throw EndOfStream();
		}
		return buf[0];
	}

	std::uint64_t read_varint() {
		std::uint64_t out {0};
		for (uint shift = 0; shift < 64; shift += 7) {
			auto val = read_byte();
			out |= (static_cast<std::uint64_t>(val & byte(0x7f)) << shift);
			if (val < byte(0x80)) {
				return out;
			}
		}
		throw ProtocolError("varint too long");
	}

	wire::Frame receive_frame() {
		wire::Frame frame;
		auto control = read_byte();
		frame.done = (control & byte(0x01)) != byte(0);
		frame.control = (control & byte(0x80)) != byte(0);
		frame.kind = static_cast<wire::Kind>((control & byte(0x7e)) >> 1);
		frame.id.stream = read_varint();
		frame.id.message = read_varint();
		auto frame_length = read_varint();
		frame.data = bytevec(frame_length, byte(0));
		auto count = asio::read(this->transport, asio::buffer(frame.data));
		if (count < frame_length) {
			throw EndOfStream();
		}
		return frame;
	}

	wire::Packet receive_packet() {
		wire::Packet pkt;
		bytevec buf;
		while (true) {
			auto frame = receive_frame();
			if (frame.control) {
				// Ignore any frames with the control bit set so that we can
				// use it in the future to mean things to people who understand
				// it.
				continue;
			}
			if (frame.id < this->remote_id) {
				throw ProtocolError("id monotonicity violation");
			}
			if (this->remote_id < frame.id) {
				// When a new ID is read, the old data is discarded. This allows
				// for easier asynchronous interrupts.
				this->remote_id = frame.id;
				buf.clear();
				pkt.id = frame.id;
				pkt.kind = frame.kind;
			} else if (frame.kind != pkt.kind) {
				throw ProtocolError("packet kind change");
			}
			buf.concat(frame.data);
			if (buf.size() > (4 << 20)) {
				throw ProtocolError("data overflow");
			}
			if (frame.done) {
				pkt.data = std::move(buf);
				return pkt;
			}
		}
	}

	bytevec receive_message() {
		while (true) {
			auto packet = receive_packet();
			switch (packet.kind) {
			case wire::Kind::Invoke:
				throw ProtocolError("invoke on existing stream");
			case wire::Kind::Message:
				return std::move(packet.data);
			case wire::Kind::Error:
				throw wire::decode_error(packet.data);
			case wire::Kind::Close:
				throw StreamClosedByPeer();
			case wire::Kind::CloseSend:
				// set eof on receive
			default:
				throw ProtocolError(
					std::string("unknown packet kind: ")
					+ std::to_string(static_cast<int>(packet.kind))
				);
			}
		}
	}
};

} // namespace drpc

#endif //DRPC_CPP_STREAM_H
