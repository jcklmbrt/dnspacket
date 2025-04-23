
#include "pch.hpp"
#include "dns.hpp"

namespace be = big_endian;

using asio::ip::udp;

std::ostream& operator<<(std::ostream &os, const std::vector<uint8_t> &buf)
{
	static constexpr size_t width = 8;

	size_t size = buf.size();
	size = ((size + (width - 1)) / width) * width;
	
	for(size_t i = 0; i < size; i++) {
		if(i >= buf.size()) {
			os << "   ";
		} else {
			os << std::hex
			   << std::setw(2)
			   << std::setfill('0')
			   << size_t(buf[i])
			   << ' ';
		}
		if((i + 1) % width == 0) {
			os << '|';
			for(size_t j = 1; j <= width; j++) {
				uint8_t ch;
				size_t index = i - width + j;
				if(index >= buf.size()) {
					ch = ' ';
				} else {
					ch = buf[index];
					if(!isprint(ch)) {
						ch = ' ';
					}
				}
				os << ch;
			}
			os << '|';
			if(i + 1 != size) {
				os << std::endl;
			}
		}
	}
	return os;
}


int main(int argc, char **argv)
{
	if(argc != 2 && argc != 3) {
		std::cerr << "Usage: dnspacket HOST SERVER" << std::endl;
		return EXIT_FAILURE;
	}

	asio::io_context io_context;

	const char *server;
	const char *host = argv[1];
	
	if(argc == 3) {
		server = argv[2];
	} else {
		std::cout << "No server provided, defaulting to: 8.8.8.8." << std::endl;
		server = "8.8.8.8";
	}

	asio::error_code ec;
	asio::ip::address address;
	
	address = asio::ip::make_address_v4(server, ec);
	if(ec) {
		std::cerr << "Bad DNS server IP address: " << ec.message() << std::endl;
		return EXIT_FAILURE;
	}
	
	udp::resolver resolver { io_context };
	udp::endpoint endpoint { address, 53 };
	udp::socket udp_socket { io_context };
	
	udp_socket.open(udp::v4());

	std::vector<uint8_t> ibuf;
	be::encoder e { ibuf };

	dns::packet dnspkt;
	dnspkt.set_flags(dns::flags::RD);
	try {
		dnspkt.add_query(dns::query(dns::name(host), dns::type::A, dns::cls::IN));
	} catch(const std::exception &e) {
		std::cerr << "Bad domain name: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}

	e << dnspkt;

	std::cout << "Sending message to: ";
	std::cout << endpoint.address().to_string() << ':' << endpoint.port();
	std::cout << std::endl << ibuf << std::endl;
	std::cout << dnspkt << std::endl;

	udp_socket.send_to(asio::buffer(ibuf), endpoint);

	uint8_t response[512] = { 0 };
	udp::endpoint sender;
	size_t len = udp_socket.receive_from(asio::buffer(response), sender);

	std::cout << "Message received from: ";
	std::cout << sender.address().to_string() << ':' << sender.port();
	std::cout << std::endl;

	be::decoder d { response };
	d >> dnspkt;
	
	std::cout << std::vector<uint8_t>(response, response + len) << std::endl;
	std::cout << dnspkt << std::endl;
	
	return 0;
}
