// Copyright (c) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

#include <deque>
#include <iostream>
#include <memory>
#include <string>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include "drpc.h"
#include "drpc/ssl.h"
#include "pb/sesamestreet.pb.h"
#include "pb/sesamestreet_drpc.pb.h"

namespace drpc::example {

namespace pb = ::sesamestreet;

using namespace std::literals::string_literals;

asio::awaitable<pb::Cookie::Type> async_secure_cookie_client(
	asio::io_service& io_service,
	std::string host,
	std::string service,
	pb::Cookie::Type type
) {
	asio::ssl::context tls_context(asio::ssl::context::tlsv13);
	tls_context.load_verify_file("cert.pem");

	auto ssl_stream = co_await drpc::ssl::async_ssl_connect(
		asio::ip::tcp::socket(io_service),
		std::move(tls_context),
		std::move(host),
		std::move(service),
		asio::use_awaitable
	);

	pb::CookieMonsterAsyncClient s {std::move(*ssl_stream)};
	pb::Cookie cookie;
	cookie.set_type(type);

	auto crumbs = co_await s.EatCookie(cookie);
	co_return crumbs.cookie().type();
}

int async_example(const std::string& hostname, const std::string& service, const std::string& cookie_type_name) {
	asio::io_service io_service;
	pb::Cookie::Type cookie_type;
	if (!pb::Cookie::Type_Parse(cookie_type_name, &cookie_type)) {
		throw std::runtime_error("invalid cookie type \""s + cookie_type_name + "\"");
	}

	auto result = asio::co_spawn(
		io_service,
		async_secure_cookie_client(io_service, hostname, service, cookie_type),
		asio::use_future
	);
	io_service.run();

	auto crumbs_type = result.get();
	std::cout << "Got crumbs from: " << pb::Cookie_Type_Name(crumbs_type) << std::endl;

	return 0;
}

pb::Cookie::Type secure_cookie_client(
	asio::io_service& io_service,
	const std::string& host,
	const std::string& service,
	pb::Cookie::Type type
) {
	asio::ssl::context tls_context(asio::ssl::context::tlsv13);
	tls_context.load_verify_file("cert.pem");

	auto ssl_stream = drpc::ssl::ssl_connect(
		asio::ip::tcp::socket(io_service),
		std::move(tls_context),
		host,
		service
	);

	pb::CookieMonsterSyncClient s {std::move(ssl_stream)};
	pb::Cookie cookie;
	cookie.set_type(type);

	auto crumbs = s.EatCookie(cookie);
	return crumbs.cookie().type();
}

int example(const std::string& hostname, const std::string& service, const std::string& cookie_type_name) {
	asio::io_service io_service;
	pb::Cookie::Type cookie_type;
	if (!pb::Cookie::Type_Parse(cookie_type_name, &cookie_type)) {
		throw std::runtime_error("invalid cookie type \""s + cookie_type_name + "\"");
	}

	auto result = secure_cookie_client(io_service, hostname, service, cookie_type);

	std::cout << "Got crumbs from: " << pb::Cookie_Type_Name(result) << std::endl;

	return 0;
}

}  // namespace drpc::example

int main(int argc, char* argv[]) {
	if (argc < 4) {
		std::cerr << "Usage: " << argv[0] << " <localhost> <host> <cookietype>\n";
		return 1;
	}
	try {
		// change this from "async_example" to "example" to run the synchronous example
		return drpc::example::async_example(argv[1], argv[2], argv[3]);
	} catch (const std::exception& e) {
		std::cerr << "Failure: " << e.what();
	}
}
