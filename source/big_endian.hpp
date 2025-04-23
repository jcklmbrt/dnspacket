#ifndef _BIG_ENDIAN_HPP
#define _BIG_ENDIAN_HPP

#include <array>
#include <vector>

namespace big_endian {

struct encoder {
	encoder(std::vector<uint8_t> &data)
		: m_data(data) {}
private:
	std::vector<uint8_t> &m_data;
public:
	void push_back(uint8_t a) { m_data.push_back(a); }
};

// encoding primitives, designed to be overloaded further for custom types
inline encoder &operator<<(encoder &e, uint8_t u8)
{
	e.push_back(u8); return e;
}
	
inline encoder &operator<<(encoder &e, uint16_t u16)
{
	return e << uint8_t(u16 >> 8)
		 << uint8_t(u16 >> 0);
}

inline encoder &operator<<(encoder &e, uint32_t u32)
{
	return e << uint8_t(u32 >> 24)
		 << uint8_t(u32 >> 16)
		 << uint8_t(u32 >>  8)
		 << uint8_t(u32 >>  0);
}

template<size_t N>
inline encoder &operator<<(encoder &e, const std::array<uint8_t, N> &bytes)
{
	for(uint8_t b : bytes) {
		e << b;
	}
	return e;
}

struct decoder { 
	template<size_t N>
	decoder(uint8_t (&data)[N], size_t len = N)
		: m_start(data), m_data(data), m_end(data + len)
	{
		assert(len <= N);
	}
private:
	uint8_t *m_start;
	uint8_t *m_data;
	uint8_t *m_end;
public:
	void seek(size_t i) { m_data = m_start + i; }
	size_t tell() { return m_data - m_start; }
	uint8_t pop_front() { assert(m_data <= m_end); return *m_data++; }
};


inline decoder &operator>>(decoder &d, uint8_t &u8)
{
	u8 = d.pop_front(); return d;
}

inline decoder &operator>>(decoder &d, uint16_t &u16)
{
	u16 = 0;
	u16 += d.pop_front() << 8;
	u16 += d.pop_front() << 0;
	return d;
}

inline decoder &operator>>(decoder &d, uint32_t &u32)
{
	u32 = 0;
	u32 += d.pop_front() << 24;
	u32 += d.pop_front() << 16;
	u32 += d.pop_front() <<  8;
	u32 += d.pop_front() <<  0;
	return d;
}

template<size_t N>
inline decoder &operator>>(decoder &d, std::array<uint8_t, N> &bytes)
{
	for(uint8_t &b : bytes) {
		d >> b;
	}
	return d;
}

}

#endif
