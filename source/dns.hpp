#ifndef _DNS_HPP
#define _DNS_HPP

#include <vector>
#include <string>

#include <asio.hpp>

#include "big_endian.hpp"

#ifdef IN
#undef IN
#endif

namespace dns {
namespace be = big_endian;

struct name {
	name() = default;
	name(std::string &&name);
	struct subname {
		size_t start;
		size_t len;
	};
private:
	std::vector<subname> m_subnames;
	std::string m_fullname;
public:
	friend be::encoder &operator<<(be::encoder &e, const name &name);
	friend be::decoder &operator>>(be::decoder &d, name &name);
	friend std::ostream &operator<<(std::ostream &os, const name &name);
	size_t encoded_size() const;
};

enum class cls : uint16_t {
	IN = 1,
	CS = 2,
	CH = 3,
	HS = 4,
	NONE = 254,
	ANY = 255
};

enum class type : uint16_t {
	A = 1,
	NS = 2,
	CNAME = 5,
	SOA = 6,
	PTR = 12,
	MX = 15,
	TXT = 16,
	AAAA = 28,
	ANY = 255
};

std::ostream &operator<<(std::ostream &os, dns::type type);
std::ostream &operator<<(std::ostream &os, dns::cls cls);

struct resource {
	resource() = default;
private:
	name m_name;
	dns::type m_type;
	dns::cls m_class;
	uint32_t m_ttl;

	uint16_t m_priority = 0;
	name m_cname;
	
	asio::ip::address m_addr;
	std::vector<std::string> m_text;
	std::vector<uint8_t> m_data;

	// soa data
	name m_mname;
	name m_rname;
	uint32_t m_serial;
	uint32_t m_refresh;
	uint32_t m_retry;
	uint32_t m_expire;
public:
	friend be::encoder &operator<<(be::encoder &e, const resource &r);
	friend be::decoder &operator>>(be::decoder &d, resource &r);
	friend std::ostream &operator<<(std::ostream &os, const resource &r);
};

struct query {
	query() = default;
	query(name &&name, type qtype, cls qclass);
private:
	name m_name;
	type m_qtype;
	cls m_qclass;
public:
	friend be::encoder &operator<<(be::encoder &e, const query &qd);
	friend be::decoder &operator>>(be::decoder &d, query &qd);
	friend std::ostream &operator<<(std::ostream &os, const query &q);
};


enum class flags : uint16_t {
	OPCODE_MASK     = 0xF << 11,
	OPCODE_STANDARD = 0,
	OPCODE_INVERSE  = 1 << 11,
	OPCODE_STATUS   = 1 << 12,

	QD = 1 << 15,
	AA = 1 << 10,
	TC = 1 << 9,
	RD = 1 << 8,
	RA = 1 << 7,

	RCODE_MASK = 0xF,
	RCODE_NO_ERROR = 0,
	RCODE_FORMAT_ERROR = 1,
	RCODE_SERVER_FAIL = 2,
	RCODE_NAME_ERROR = 3,
	RCODE_NOT_IMPLEMENTED = 4,
	RCODE_REFUSED = 5
};

flags operator|(flags fa, flags fb);
flags operator&(flags fa, flags fb);
std::ostream &operator<<(std::ostream &os, flags f);

struct packet {
	packet();
	void add_query(query &&query);
	void set_flags(flags flag);
private:
	uint16_t m_id;
	flags m_flags;
	std::vector<query> m_queries;
	std::vector<resource> m_answers;
	std::vector<resource> m_authorities;
	std::vector<resource> m_additionals;
public:
	friend be::encoder &operator<<(be::encoder &e, const packet &pkt);
	friend be::decoder &operator>>(be::decoder &d, packet &pkt);
	friend std::ostream &operator<<(std::ostream &os, const packet &pkt);
};

}
#endif
