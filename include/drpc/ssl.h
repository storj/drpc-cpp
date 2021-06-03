// Copyright (c) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

#ifndef DRPC_CPP_SSL_H
#define DRPC_CPP_SSL_H

#include <iterator>
#include <memory>
#include <string>
#include <utility>

#include <asio/ssl.hpp>
#include <openssl/x509.h>

#include "drpc.h"

namespace drpc::ssl {

namespace detail {

template <typename T, typename ValueType = decltype(std::declval<T>()[0])>
class indexing_based_iterator {
public:
	using iterator_type = indexing_based_iterator<T, ValueType>;
	using iterator_category = std::random_access_iterator_tag;
	using difference_type = int;
	using value_type = ValueType;
	using pointer = ValueType*;
	using reference = ValueType&;

	indexing_based_iterator(T* t, int num)
		: t {t}
		, assigned {false}
		, val {}
		, num {num}
	{}

	indexing_based_iterator(const iterator_type& rhs) noexcept = default;

	indexing_based_iterator(iterator_type&& rhs) noexcept = default;

	indexing_based_iterator& operator=(const iterator_type& rhs) noexcept = default;

	indexing_based_iterator& operator=(iterator_type&& rhs) noexcept = default;

	reference operator*() const {
		if (!assigned) {
			val = t[num];
		}
		return val;
	}

	pointer operator->() {
		if (!assigned) {
			val = t[num];
		}
		return &val;
	}

	iterator_type& operator++() noexcept {
		++num;
		return *this;
	}

	iterator_type& operator--() noexcept {
		--num;
		return *this;
	}

	iterator_type operator++(int) noexcept {
		iterator_type tmp {*this};
		++num;
		return tmp;
	}

	iterator_type operator--(int) noexcept {
		iterator_type tmp {*this};
		--num;
		return tmp;
	}

	iterator_type& operator+=(int n) noexcept {
		num += n;
		return *this;
	}

	iterator_type& operator-=(int n) noexcept {
		num -= n;
		return *this;
	}

	ValueType operator[](int n) {
		return *(*this + n);
	}

	friend bool operator==(const iterator_type& a, const iterator_type& b) noexcept {
		return a.num == b.num;
	}

	friend bool operator!=(const iterator_type& a, const iterator_type& b) noexcept {
		return a.num != b.num;
	}

	friend bool operator<(const iterator_type& a, const iterator_type& b) noexcept {
		return a.num < b.num;
	}

	friend bool operator>(const iterator_type& a, const iterator_type& b) noexcept {
		return a.num > b.num;
	}

	friend bool operator<=(const iterator_type& a, const iterator_type& b) noexcept {
		return a.num <= b.num;
	}

	friend bool operator>=(const iterator_type& a, const iterator_type& b) noexcept {
		return a.num >= b.num;
	}

	friend iterator_type operator+(const iterator_type& i, int n) noexcept {
		return iterator_type {i.t, i.num + n};
	}

	friend iterator_type operator-(const iterator_type& i, int n) noexcept {
		return iterator_type {i.t, i.num - n};
	}

	friend iterator_type operator+(int n, const iterator_type& i) noexcept {
		return iterator_type {i.t, i.num + n};
	}

	friend iterator_type operator-(int n, const iterator_type& i) noexcept {
		return iterator_type {i.t, i.num - n};
	}

	friend difference_type operator-(const iterator_type& a, const iterator_type& b) noexcept {
		return a.num - b.num;
	}

private:
	T* t;
	bool assigned;
	ValueType val;
	int num;
};

std::string oid_from_asn1_object(::ASN1_OBJECT* obj) {
	char buf[1024];
	int len = ::OBJ_obj2txt(buf, sizeof(buf), obj, 0);
	return std::string(buf, len);
}

std::string str_from_asn1_string(::ASN1_STRING* str) {
	int len = ::ASN1_STRING_length(str);
	const uint8_t* data = ::ASN1_STRING_get0_data(str);
	return std::string(reinterpret_cast<const char*>(data), len);
}

} // namespace detail

class X509NameEntry {
public:
	X509NameEntry() = default;

	explicit X509NameEntry(::X509_NAME_ENTRY* entryp) noexcept : entryp {entryp} {
	}

	explicit operator bool() const noexcept {
		return (entryp != nullptr);
	}

	std::string get_object() {
		auto obj = ::X509_NAME_ENTRY_get_object(entryp);
		// will we ever be given an X509_NAME with no ASN1_OBJECT for its field?
		return detail::oid_from_asn1_object(obj);
	}

	std::string get_value() {
		auto data = ::X509_NAME_ENTRY_get_data(entryp);
		// will we ever be given an X509_NAME with no ASN1_STRING for its data?
		return detail::str_from_asn1_string(data);
	}

private:
	::X509_NAME_ENTRY* entryp;
};

class X509Name {
public:
	X509Name() = default;

	explicit X509Name(::X509_NAME* namep) noexcept : namep {namep} {
	}

	explicit operator bool() const noexcept {
		return (namep != nullptr);
	}

	using iterator = detail::indexing_based_iterator<X509Name, const X509NameEntry>;

	iterator begin() {
		return iterator {this, 0};
	}

	iterator end() {
		auto num = ::X509_NAME_entry_count(namep);
		return iterator {this, num};
	}

	X509NameEntry operator[](int n) const {
		return X509NameEntry(::X509_NAME_get_entry(namep, n));
	}

private:
	::X509_NAME* namep;
};

class X509Certificate {
public:
	explicit X509Certificate(::X509* certp) noexcept : certp {certp} {
	}

	explicit operator bool() const noexcept {
		return (certp != nullptr);
	}

	// caller is responsible for making sure the name object is not used after this
	// certificate object goes out of scope
	X509Name get_subject_name() const {
		return X509Name(::X509_get_subject_name(certp));
	}

private:
	::X509* certp;
};

class TLSVerifyContext {
public:
	explicit TLSVerifyContext(::X509_STORE_CTX* store_ctx) noexcept : store_ctx {store_ctx} {
	}

	explicit operator bool() const noexcept {
		return (store_ctx != nullptr);
	}

	// caller is responsible for making sure the cert is not used after this
	// context object goes out of scope
	[[nodiscard]] X509Certificate get_current_cert() const {
		auto cert = ::X509_STORE_CTX_get_current_cert(store_ctx);
		return X509Certificate {cert};
	}

private:
	::X509_STORE_CTX* store_ctx;
};

namespace detail {

template <typename SocketType>
asio::awaitable<std::optional<asio::ssl::stream<SocketType>>> async_ssl_connect_co(
	SocketType socket,
	asio::ssl::context ssl_ctx,
	const std::string& host,
	const std::string& service
) {
	auto executor = socket.get_executor();
	auto resolver = typename SocketType::protocol_type::resolver(executor);
	auto lookup_results = co_await resolver.async_resolve(host, service, asio::use_awaitable);
	co_await asio::async_connect(
		socket.lowest_layer(), lookup_results, asio::use_awaitable
	);
	asio::ssl::stream<SocketType> stream {std::move(socket), ssl_ctx};
	co_await stream.async_handshake(asio::ssl::stream_base::client, asio::use_awaitable);
	co_return std::optional<asio::ssl::stream<SocketType>>(std::move(stream));
}

} // namespace detail

// Resolve a hostname and service name, connect the socket, and complete an
// asynchronous SSL handshake before passing the stream on to the completion
// token.
//
// We are taking most of these arguments by value, so that we can take ownership
// and move them from place to place until we are done with them.
// asio::ssl::context in particular can't be copied, and if the arguments here
// were passed by reference, they might go out of scope before we are able to
// call into the coroutine. shared_ptr<> would work instead, but we shouldn't
// actually need its functionality, so we'll forgo the thread synchronization
// overhead.
template <typename SocketType, typename CompletionToken>
asio::awaitable<std::optional<asio::ssl::stream<SocketType>>> async_ssl_connect(
	SocketType socket,
	asio::ssl::context ssl_ctx,
	std::string host,
	std::string service,
	CompletionToken&& token
) {
	return asio::co_spawn(
		socket.get_executor(),
		[
			socket = std::move(socket),
			ssl_ctx = std::move(ssl_ctx),
			host = std::move(host),
			service = std::move(service)
		]() mutable {
			return detail::async_ssl_connect_co(
				std::move(socket), std::move(ssl_ctx), std::move(host), std::move(service)
			);
		},
		std::forward<CompletionToken>(token)
	);
}

template <typename SocketType>
asio::ssl::stream<SocketType> ssl_connect(
	SocketType socket,
	asio::ssl::context ssl_ctx,
	const std::string& host,
	const std::string& service
) {
	auto executor = socket.get_executor();
	auto resolver = typename SocketType::protocol_type::resolver(executor);
	auto lookup_results = resolver.resolve(host, service);
	asio::connect(socket.lowest_layer(), lookup_results);
	asio::ssl::stream<SocketType> stream {std::move(socket), ssl_ctx};
	stream.handshake(asio::ssl::stream_base::client);
	return stream;
}

}  // namespace drpc::ssl

#endif  // DRPC_CPP_SSL_H
