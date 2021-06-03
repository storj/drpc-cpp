// Copyright (c) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

#ifndef DRPC_CPP_CONCEPTS_H
#define DRPC_CPP_CONCEPTS_H

#include <cstddef>
#include <string>
#include <type_traits>

#include <asio.hpp>

#include <drpc/wire.h>

namespace drpc {

using error_code = asio::error_code;

template <typename T, typename U>
concept is_convertible = std::is_convertible_v<T, U>;

template <typename T, typename U>
concept is_nothrow_convertible = std::is_nothrow_convertible_v<T, U>;

template <typename T>
concept HasASIOExecutor = requires(T& t) {
	typename T::executor_type;
	{ t.get_executor() } -> asio::execution::executor;
};

template <typename T>
concept SyncReadTransport = HasASIOExecutor<T> && requires(T& t, asio::mutable_buffer& buf, error_code& ec) {
	{ t.read_some(buf) } -> is_nothrow_convertible<std::size_t>;
	{ t.read_some(buf, ec) } -> is_nothrow_convertible<std::size_t>;
};

static_assert(SyncReadTransport<asio::posix::basic_stream_descriptor<>>);

template <typename T>
concept SyncWriteTransport = HasASIOExecutor<T> && requires(T& t, const asio::const_buffer& buf, error_code& ec) {
	{ t.write_some(buf) } -> is_nothrow_convertible<std::size_t>;
	{ t.write_some(buf, ec) } -> is_nothrow_convertible<std::size_t>;
};

static_assert(SyncWriteTransport<asio::posix::basic_stream_descriptor<>>);

template <typename T>
concept AsyncReadTransport = HasASIOExecutor<T> && requires(T& t, asio::mutable_buffer& buf) {
	t.async_read_some(buf, asio::use_awaitable);
};

static_assert(AsyncReadTransport<asio::posix::basic_stream_descriptor<>>);

template <typename T>
concept AsyncWriteTransport = HasASIOExecutor<T> && requires(T& t, const asio::const_buffer& buf, asio::detached_t tok) {
	t.async_write_some(buf, tok);
};

static_assert(AsyncWriteTransport<asio::posix::basic_stream_descriptor<>>);

template <typename T>
concept SimpleCloseable = requires(T& t) {
	t.lowest_layer().close();
};

template <typename T>
concept CloseableWithErrorCode = requires(T& t, error_code& ec) {
	{ t.lowest_layer().close(ec) } noexcept;
};

template <typename T>
concept Closeable = SimpleCloseable<T> || CloseableWithErrorCode<T>;

template <typename T>
concept SyncTransport = SyncWriteTransport<T> && SyncReadTransport<T> && Closeable<T>;

template <typename T>
concept AsyncTransport = AsyncWriteTransport<T> && AsyncReadTransport<T> && Closeable<T>;

template <typename T>
concept Transport = SyncTransport<T> || AsyncTransport<T>;

template <typename P>
concept MetadataProvider = requires(P& p, bytevec& os, const std::string& s) {
	{ p[s] } -> is_convertible<std::string>;
	{ wire::encode_metadata(os, p) };
};

template <typename M>
concept MessageType = requires(const M& m, bytevec& buf) {
	{ wire::encode_message(m, buf) } -> is_nothrow_convertible<bool>;
} && requires(M& m, const bytevec& buf) {
	{ wire::decode_message(m, buf) } -> is_nothrow_convertible<bool>;
};

} // namespace drpc

#endif //DRPC_CPP_CONCEPTS_H
