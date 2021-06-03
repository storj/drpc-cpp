// Copyright (c) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

#ifndef DRPC_CPP_CONN_H
#define DRPC_CPP_CONN_H

#include <memory>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>

#include <drpc/concepts.h>
#include <drpc/wire.h>
#include <drpc/stream.h>

namespace drpc {

template <typename TransportT>
class ConnBase {
public:
	using TransportType = TransportT;

	explicit ConnBase(TransportT t)
		: transport {std::move(t)}
		, is_closed {false} {
	}

	template <typename T = TransportT, typename = std::enable_if_t<CloseableWithErrorCode<T>>>
	void close(error_code& e) noexcept {
		is_closed = true;
		transport.lowest_layer().close(e);
	}

	template <typename T = TransportT, typename = std::enable_if_t<SimpleCloseable<T>>>
	void close() {
		is_closed = true;
		transport.lowest_layer().close();
	}

	[[nodiscard]] bool closed() const noexcept {
		return is_closed;
	}

	TransportType& get_transport() noexcept {
		return transport;
	}

protected:
	template <MetadataProvider MetadataT, MessageType InputMessageT>
	std::pair<bytevec, bytevec> prepare_invoke(MetadataT& meta, const InputMessageT& in) {
		bytevec metadata_buf;
		wire::encode_metadata(metadata_buf, meta);
		bytevec request_bytes;
		if (!wire::encode_message(in, request_bytes)) {
			throw SerializationError("failed to serialize message");
		}
		return {request_bytes, metadata_buf};
	}

	template <MessageType OutputMessageT>
	void complete_invoke(const bytevec& bytes, OutputMessageT& out) {
		if (!wire::decode_message(out, bytes)) {
			throw SerializationError("failed to deserialize message");
		}
	}

	TransportType transport;
	bool is_closed;
	std::uint64_t sid;
};

template <AsyncTransport TransportT>
class AsyncConn : public ConnBase<TransportT> {
public:
	using ConnBase<TransportT>::ConnBase;
	using typename ConnBase<TransportT>::TransportType;

	template <
		MetadataProvider MetadataT,
		MessageType InputMessageT,
		MessageType OutputMessageT
	>
	asio::awaitable<void> async_invoke(
		MetadataT& meta,
		const bytevec& rpc,
		const InputMessageT& in,
		OutputMessageT& out
	) {
		auto [request_bytes, metadata_bytes] = this->prepare_invoke(meta, in);
		auto stream = make_client_stream(this->transport);

		if (!metadata_bytes.empty()) {
			co_await stream->async_send_packet(wire::Kind::InvokeMetadata, std::move(metadata_bytes));
		}
		co_await stream->async_send_packet(wire::Kind::Invoke, rpc);
		co_await stream->async_send_packet(wire::Kind::Message, request_bytes);
		auto response_bytes = co_await stream->async_receive_message();
		this->complete_invoke(response_bytes, out);
	}

protected:
	std::shared_ptr<AsyncRPCStream<TransportT>> make_client_stream(TransportT& transport) {
		++this->sid;
		auto stream = std::make_shared<AsyncRPCStream<TransportT>>(transport, this->sid);
		this->prev_stream = stream;
		return stream;
	}

	std::shared_ptr<AsyncRPCStream<TransportType>> prev_stream;
};

template <SyncTransport TransportT>
class Conn : public ConnBase<TransportT> {
public:
	using ConnBase<TransportT>::ConnBase;
	using typename ConnBase<TransportT>::TransportType;

	template <
		MetadataProvider MetadataT,
		MessageType InputMessageT,
		MessageType OutputMessageT
	>
	void invoke(
		MetadataT& meta,
		const bytevec& rpc,
		const InputMessageT& in,
		OutputMessageT& out
	) {
		auto [request_bytes, metadata_bytes] = this->prepare_invoke(meta, in);
		auto stream = make_client_stream(this->transport);
		if (!metadata_bytes.empty()) {
			stream->send_packet(wire::Kind::InvokeMetadata, std::move(metadata_bytes));
		}

		stream->send_packet(wire::Kind::Invoke, rpc);
		stream->send_packet(wire::Kind::Message, request_bytes);
		auto response_bytes = stream->receive_message();
		this->complete_invoke(response_bytes, out);
	}

protected:
	std::shared_ptr<RPCStream<TransportT>> make_client_stream(TransportT& transport) {
		++this->sid;
		auto stream = std::make_shared<RPCStream<TransportT>>(transport, this->sid);
		this->prev_stream = stream;
		return stream;
	}

	std::shared_ptr<RPCStream<TransportType>> prev_stream;
};

} // namespace drpc

#endif //DRPC_CPP_CONN_H
