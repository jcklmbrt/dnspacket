#include "pch.hpp"
#include "dns.hpp"

namespace be = big_endian;

dns::name::name(std::string &&name)
	: m_fullname(std::move(name))
{
	size_t size = m_fullname.size();
	size_t start = 0;
	while(start < size) {
		size_t dot = m_fullname.find('.', start);
		if(dot != std::string::npos) {
			// found dot
			m_subnames.emplace_back(subname{start, dot - start});
			start = dot + 1;
		} else {
			m_subnames.emplace_back(subname{start, size - start});
			break;
		}
	}
}


be::encoder &dns::operator<<(be::encoder &e, const dns::name &name)
{
	for(const dns::name::subname &sn : name.m_subnames) {
		e << uint8_t(sn.len);
		for(size_t i = sn.start; i < sn.start + sn.len; i++) {
			e << uint8_t(name.m_fullname[i]);
		}
	}
	return e << uint8_t(0);
}


be::decoder &dns::operator>>(be::decoder &d, dns::name &name)
{
	size_t maxname = 255;
	std::string fullname;

	uint8_t len;
	size_t ofs = 0;

	d >> len;
	
	while(maxname-- && len) {
		// the rest of the name is elsewhere in the packet
		if((len & 0xC0) == 0xC0) {
			size_t back = ((len & 0x3F) << 8) | d.pop_front();
			if(ofs == 0) {
				ofs = d.tell();
			}
			d.seek(back);
			d >> len;
		}

		while(len--) {
			fullname.push_back(d.pop_front());
		}

		d >> len;
		if(len == 0) {
			break;
		} else {
			fullname.push_back('.');
		}
	}

	name = dns::name(std::move(fullname));

	if(ofs != 0) {
		d.seek(ofs);
	}
		
	return d;
}

std::ostream &dns::operator<<(std::ostream &os, const dns::name &name)
{
	return os << name.m_fullname;
}


size_t dns::name::encoded_size() const
{
	size_t totalsize = 0;
	for(const dns::name::subname &sn : m_subnames) {
		totalsize++; // for length prefix
		totalsize += sn.len; // for subname
	}
	return totalsize;
}


be::encoder &dns::operator<<(be::encoder &e, const dns::resource &r)
{
	e << r.m_name
	  << static_cast<uint16_t>(r.m_type)
	  << static_cast<uint16_t>(r.m_class)
	  << r.m_ttl;

	uint16_t len = 0;

	switch(r.m_type) {
	case dns::type::MX: len = sizeof(r.m_priority); [[fallthrough]];
	case dns::type::NS: [[fallthrough]];
	case dns::type::PTR: [[fallthrough]];
	case dns::type::CNAME: len += r.m_cname.encoded_size(); break;
	case dns::type::A: len = 4; break;
	case dns::type::AAAA: len = 16; break;
	case dns::type::SOA:
		len += r.m_mname.encoded_size();
		len += r.m_rname.encoded_size();
		len += sizeof(r.m_serial);
		len += sizeof(r.m_refresh);
		len += sizeof(r.m_retry);
		len += sizeof(r.m_expire);
		break;
	case dns::type::TXT:
		for(const std::string &s : r.m_text) {
			len += s.size() + 1;
		}
		break;
	default: len = r.m_data.size(); break;
	}

	e << len;

	switch(r.m_type) {
	case dns::type::MX:
		e << r.m_priority;
		[[fallthrough]];
	case dns::type::NS: [[fallthrough]];
	case dns::type::PTR: [[fallthrough]];
	case dns::type::CNAME:
		e << r.m_cname;
		break;
	case dns::type::A:
		e << r.m_addr.to_v4().to_bytes();
		break;
	case dns::type::AAAA:
		e << r.m_addr.to_v6().to_bytes();
		break;
	case dns::type::TXT:
		for(const std::string &s : r.m_text) {
			e << uint8_t(s.size());
			for(uint8_t c : s) {
				e << c;
			}
		}
		break;
	case dns::type::SOA:
		e << r.m_mname
		  << r.m_rname
		  << r.m_serial
		  << r.m_refresh
		  << r.m_retry
		  << r.m_expire;
		break;
	default:
		for(size_t i = 0; i < len; i++) {
			e << r.m_data[i];
		}
		break;
	}
	
	return e;
}


be::decoder &dns::operator>>(be::decoder &d, dns::resource &r)
{
	uint16_t type;
	uint16_t cls;
	
	d >> r.m_name
	  >> type
	  >> cls
	  >> r.m_ttl;

	r.m_type = static_cast<dns::type>(type);
	r.m_class = static_cast<dns::cls>(cls);

	uint16_t len;
	d >> len;
	
	switch(r.m_type) {
	case dns::type::MX:
		d >> r.m_priority;
		[[fallthrough]];
	case dns::type::NS: [[fallthrough]];
	case dns::type::PTR: [[fallthrough]];
	case dns::type::CNAME:
		d >> r.m_cname;
		break;
	case dns::type::A:
		if(len == 4) {
			std::array<uint8_t, 4> ipv4;
			d >> ipv4;
			r.m_addr = asio::ip::make_address_v4(ipv4);
		}
		break;
	case dns::type::AAAA:
		if(len == 16) {
			std::array<uint8_t, 16> ipv6;
			d >> ipv6;
			r.m_addr = asio::ip::make_address_v6(ipv6);
		}
		break;
	case dns::type::SOA:
		d >> r.m_mname
		  >> r.m_rname
		  >> r.m_serial
		  >> r.m_refresh
		  >> r.m_retry
		  >> r.m_expire;
		break;
	case dns::type::TXT:
		uint8_t b;
		// entire buffer is length prefixed with len
		while(len--) {
			// each string is length prefixed with a byte
			std::string &s = r.m_text.emplace_back();
			for(d >> b; b--; len--) {
				s.push_back(d.pop_front());
			}
		}
		break;
	default:
		while(len--) {
			r.m_data.push_back(d.pop_front());
		}
		break;
	}
	
	return d;
}


std::ostream &dns::operator<<(std::ostream &os, const dns::resource &r)
{
	os << "RR:" << std::endl
	   << "\tNAME:  " << r.m_name << std::endl
	   << "\tTYPE:  " << r.m_type << std::endl
	   << "\tCLASS: " << r.m_class << std::endl
	   << "\tTTL:   " << std::dec << r.m_ttl << std::endl;

	os << "\tDATA: ";
	switch(r.m_type) {
	case dns::type::A:     [[fallthrough]];
	case dns::type::AAAA:  os << r.m_addr; break;
	case dns::type::MX:    os << r.m_priority << ' '; [[fallthrough]];
	case dns::type::NS:    [[fallthrough]];
	case dns::type::PTR:   [[fallthrough]];
	case dns::type::CNAME: os << r.m_cname; break;
	case dns::type::SOA:
		os << "SOA" << std::endl;
		os << "\t\tMNAME: " << r.m_mname << std::endl;
		os << "\t\tRNAME: " << r.m_rname << std::endl;
		os << "\t\tSERIAL: " << r.m_serial << std::endl;
		os << "\t\tREFRESH: " << r.m_refresh << std::endl;
		os << "\t\tRETRY: " << r.m_retry << std::endl;
		os << "\t\tEXPIRE: " << r.m_expire << std::endl;
	case dns::type::TXT:
		for(const std::string &s : r.m_text) {
			os << '\t' << s << std::endl;
		}
		break;
	default:
		for(size_t i = 0; i < r.m_data.size(); i++) {
			os << std::hex << std::setw(2) << uint16_t(r.m_data[i]);
			if(i + 1 != r.m_data.size()) {
				os << ' ';
			}
		}
		break;
	}
	
	return os << std::endl;
}


dns::query::query(name &&name, type qtype, cls qclass)
	: m_name(std::move(name)),
	  m_qtype(qtype),
	  m_qclass(qclass)
{
	
}

be::encoder &dns::operator<<(be::encoder &e, const dns::query &qd)
{
	return e << qd.m_name
		 << static_cast<uint16_t>(qd.m_qtype)
		 << static_cast<uint16_t>(qd.m_qclass);
}

be::decoder &dns::operator>>(be::decoder &d, dns::query &qd)
{
	uint16_t qtype;
	uint16_t qclass;
	
	d >> qd.m_name
	  >> qtype
	  >> qclass;
	
	qd.m_qtype = static_cast<dns::type>(qtype);
	qd.m_qclass = static_cast<dns::cls>(qclass);

	return d;
	
}
std::ostream &dns::operator<<(std::ostream &os, const dns::query &q)
{
	return os << "QD:" << std::endl
		  << "\tNAME:  " << q.m_name << std::endl
		  << "\tTYPE:  " << q.m_qtype << std::endl
		  << "\tCLASS: " << q.m_qclass << std::endl;
}

std::ostream &dns::operator<<(std::ostream &os, dns::type type)
{
	switch(type) {
	case dns::type::A: os << "A";  break;
	case dns::type::NS: os << "NS"; break;
	case dns::type::CNAME: os << "CNAME"; break;
	case dns::type::SOA: os << "SOA"; break;
	case dns::type::PTR: os << "PTR"; break;
	case dns::type::MX: os << "MX"; break;
	case dns::type::TXT: os << "TXT"; break;
	case dns::type::AAAA: os << "AAAA"; break;
	case dns::type::ANY: os << "ANY"; break;
	default: os << static_cast<uint16_t>(type); break;
	}
	return os;
}

std::ostream &dns::operator<<(std::ostream &os, dns::cls cls)
{
	switch(cls) {
	case dns::cls::IN: os << "IN"; break;
	case dns::cls::CS: os << "CS"; break;
	case dns::cls::CH: os << "CH"; break;
	case dns::cls::HS: os << "HS"; break;
	case dns::cls::NONE: os << "NONE"; break;
	case dns::cls::ANY: os << "ANY"; break;
	default: os << static_cast<uint16_t>(cls); break;
	}
	return os;
}


dns::flags dns::operator|(dns::flags fa, dns::flags fb)
{
	uint16_t a = static_cast<uint16_t>(fa);
	uint16_t b = static_cast<uint16_t>(fb);
	return static_cast<dns::flags>(a | b);
}

dns::flags dns::operator&(dns::flags fa, dns::flags fb)
{
	uint16_t a = static_cast<uint16_t>(fa);
	uint16_t b = static_cast<uint16_t>(fb);
	return static_cast<dns::flags>(a & b);
}

std::ostream &dns::operator<<(std::ostream &os, dns::flags f)
{
	os << "FLAGS:" << std::endl;

	if(static_cast<uint16_t>(f & dns::flags::QD)) {
		os << "\tRESPONSE" << std::endl;
		switch(f & dns::flags::RCODE_MASK) {
		case dns::flags::RCODE_NO_ERROR:
			os << "\tRCODE_NO_ERROR" << std::endl;
			break;
		case dns::flags::RCODE_FORMAT_ERROR:
			os << "\tRCODE_FORMAT_ERROR" << std::endl;
			break;
		case dns::flags::RCODE_SERVER_FAIL:
			os << "\tRCODE_SERVER_FAIL" << std::endl;
			break;
		case dns::flags::RCODE_NAME_ERROR:
			os << "\tRCODE_NAME_ERROR" << std::endl;
			break;
		case dns::flags::RCODE_NOT_IMPLEMENTED:
			os << "\tRCODE_NOT_IMPLEMENTED" << std::endl;
			break;
		case dns::flags::RCODE_REFUSED:
			os << "\tRCODE_REFUSED" << std::endl;
			break;
		default:
			break;
		}
	} else {
		os << "\tQUERY" << std::endl;
		switch(f & dns::flags::OPCODE_MASK) {
		case dns::flags::OPCODE_STANDARD:
			os << "\tOPCODE_STANDARD" << std::endl;
			break;
		case dns::flags::OPCODE_INVERSE:
			os << "\tOPCODE_INVERSE" << std::endl;
			break;
		case dns::flags::OPCODE_STATUS:
			os << "\tOPCODE_STATUS" << std::endl;
			break;
		default:
			break;
		}
	}

	if(static_cast<uint16_t>(f & dns::flags::AA)) {
		os << "\tAuthoritative Answer" << std::endl;
	}
	if(static_cast<uint16_t>(f & dns::flags::TC)) {
		os << "\tTruncated" << std::endl;
	}
	if(static_cast<uint16_t>(f & dns::flags::RD)) {
		os << "\tRecursion Desired" << std::endl;
	}
	if(static_cast<uint16_t>(f & dns::flags::RA)) {
		os << "\tRecursion Available" << std::endl;
	}

	return os;
}

dns::packet::packet()
{
	m_id = ('H' << 8) + 'I';
	m_flags = dns::flags::OPCODE_STANDARD;
}

void dns::packet::add_query(dns::query &&query)
{
	m_queries.push_back(std::move(query));
}

void dns::packet::set_flags(dns::flags flags)
{
	m_flags = m_flags | flags;
}
	
be::encoder &dns::operator<<(be::encoder &e, const dns::packet &pkt)
{
	uint16_t qdcount = pkt.m_queries.size();
	uint16_t ancount = pkt.m_answers.size();
	uint16_t nscount = pkt.m_authorities.size();
	uint16_t arcount = pkt.m_additionals.size();

	e << pkt.m_id
	  << static_cast<uint16_t>(pkt.m_flags)
	  << qdcount
	  << ancount
	  << nscount
	  << arcount;

	for(const query &qd : pkt.m_queries) {
		e << qd;
	}

	for(const resource &an : pkt.m_answers) {
		e << an;
	}

	for(const resource &ns : pkt.m_authorities) {
		e << ns;
	}

	for(const resource &ar : pkt.m_additionals) {
		e << ar;
	}

	return e;
}
	
be::decoder &dns::operator>>(be::decoder &d, dns::packet &pkt)
{
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;

	d >> pkt.m_id
	  >> flags
	  >> qdcount
	  >> ancount
	  >> nscount
	  >> arcount;

	pkt.m_flags = static_cast<dns::flags>(flags);

	pkt.m_queries.resize(qdcount);
	for(uint16_t i = 0; i < qdcount; i++) {
		d >> pkt.m_queries[i];
	}

	pkt.m_answers.resize(ancount);
	for(uint16_t i = 0; i < ancount; i++) {
		d >> pkt.m_answers[i];
	}

	pkt.m_authorities.resize(nscount);
	for(uint16_t i = 0; i < nscount; i++) {
		d >> pkt.m_authorities[i];
	}

	pkt.m_additionals.resize(arcount);
	for(uint16_t i = 0; i < arcount; i++) {
		d >> pkt.m_additionals[i];
	}

	return d;
}

std::ostream &dns::operator<<(std::ostream &os, const dns::packet &pkt)
{
	os << "ID: " << std::hex << pkt.m_id << std::endl;
	os << pkt.m_flags;
		
	for(const query &qd : pkt.m_queries) {
		os << qd;
	}

	for(const resource &an : pkt.m_answers) {
		os << an;
	}

	for(const resource &ns : pkt.m_authorities) {
		os << ns;
	}

	for(const resource &ar : pkt.m_additionals) {
		os << ar;
	}

	return os;
}
