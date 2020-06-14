/*
The MIT License (MIT)

Copyright (c) 2013-2015 winlin

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <htl_stdinc.hpp>

#include <inttypes.h>
#include <assert.h>
#include <st.h>


#include <malloc.h>


#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>

#include <unistd.h>

#include <netinet/udp.h>

#include <string>
#include <sstream>
using namespace std;

#include <htl_core_error.hpp>
#include <htl_core_log.hpp>

#include <htl_app_ps_publish.hpp>
#include <htl_app_rtmp_protocol.hpp>

#include <assert.h>

bool srs_is_little_endian2()
{
    // convert to network(big-endian) order, if not equals, 
    // the system is little-endian, so need to convert the int64
    static int little_endian_check = -1;
    
    if(little_endian_check == -1) {
        union {
            int32_t i;
            int8_t c;
        } little_check_union;
        
        little_check_union.i = 0x01;
        little_endian_check = little_check_union.c;
    }
    
    return (little_endian_check == 1);
}

SrsRtpHeader::SrsRtpHeader()
{
    padding          = false;
    padding_length   = 0;
    extension        = false;
    cc               = 0;
    marker           = false;
    payload_type     = 0;
    sequence         = 0;
    timestamp        = 0;
    ssrc             = 0;
    extension_length = 0;
}

void SrsRtpHeader::reset()
{
    // We only reset the optional fields, the required field such as ssrc
    // will always be set by user.
    padding          = false;
    extension        = false;
    cc               = 0;
    marker           = false;
    extension_length = 0;
}

SrsRtpHeader::~SrsRtpHeader()
{
}

int SrsRtpHeader::decode(SrsBuffer2* buf)
{
    int err = 0;

    if (buf->size() < kRtpHeaderFixedSize) {
        return -1;
    }

    /*   
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |V=2|P|X|  CC   |M|     PT      |       sequence number         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           timestamp                           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |           synchronization source (SSRC) identifier            |
     +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
     |            contributing source (CSRC) identifiers             |
     |                             ....                              |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */

    uint8_t first = buf->read_1bytes();
    padding = (first & 0x20);
    extension = (first & 0x10);
    cc = (first & 0x0F);

    uint8_t second = buf->read_1bytes();
    marker = (second & 0x80);
    payload_type = (second & 0x7F);

    sequence = buf->read_2bytes();
    timestamp = buf->read_4bytes();
    ssrc = buf->read_4bytes();

    if (!buf->require(nb_bytes())) {
        return -1;
    }

    for (uint8_t i = 0; i < cc; ++i) {
        csrc[i] = buf->read_4bytes();
    }    

    if (extension) {
        uint16_t profile_id = buf->read_2bytes();
        extension_length = buf->read_2bytes();

        // TODO: FIXME: Read extensions.
        // @see: https://tools.ietf.org/html/rfc3550#section-5.3.1
        buf->skip(extension_length * 4);

        // @see: https://tools.ietf.org/html/rfc5285#section-4.2
        if (profile_id == 0xBEDE) {
            // TODO: FIXME: Implements it.
        }    
    }

    if (padding) {
        padding_length = *(reinterpret_cast<uint8_t*>(buf->data() + buf->size() - 1));
        if (!buf->require(padding_length)) {
            return -1;
        }
    }

    return err;
}

int SrsRtpHeader::encode(SrsBuffer2* buf)
{
    int err = 0;

    // Encode the RTP fix header, 12bytes.
    // @see https://tools.ietf.org/html/rfc1889#section-5.1
    char* op = buf->head();
    char* p = op;

    // The version, padding, extension and cc, total 1 byte.
    uint8_t v = 0x80 | cc;
    if (padding) {
        v |= 0x20;
    }
    if (extension) {
        v |= 0x10;
    }
    *p++ = v;

    // The marker and payload type, total 1 byte.
    v = payload_type;
    if (marker) {
        v |= kRtpMarker;
    }
    *p++ = v;

    // The sequence number, 2 bytes.
    char* pp = (char*)&sequence;
    *p++ = pp[1];
    *p++ = pp[0];

    // The timestamp, 4 bytes.
    pp = (char*)&timestamp;
    *p++ = pp[3];
    *p++ = pp[2];
    *p++ = pp[1];
    *p++ = pp[0];

    // The SSRC, 4 bytes.
    pp = (char*)&ssrc;
    *p++ = pp[3];
    *p++ = pp[2];
    *p++ = pp[1];
    *p++ = pp[0];

    // The CSRC list: 0 to 15 items, each is 4 bytes.
    for (size_t i = 0; i < cc; ++i) {
        pp = (char*)&csrc[i];
        *p++ = pp[3];
        *p++ = pp[2];
        *p++ = pp[1];
        *p++ = pp[0];
    }

    // TODO: Write exteinsion field.
    if (extension) {
    }

    // Consume the data.
    buf->skip(p - op);

    return err;
}

int SrsRtpHeader::nb_bytes()
{
    return kRtpHeaderFixedSize + cc * 4 + (extension ? (extension_length + 1) * 4 : 0);
}

void SrsRtpHeader::set_marker(bool v)
{
    marker = v;
}

bool SrsRtpHeader::get_marker() const
{
    return marker;
}

void SrsRtpHeader::set_payload_type(uint8_t v)
{
    payload_type = v;
}

uint8_t SrsRtpHeader::get_payload_type() const
{
    return payload_type;
}

void SrsRtpHeader::set_sequence(uint16_t v)
{
    sequence = v;
}

uint16_t SrsRtpHeader::get_sequence() const
{
    return sequence;
}

void SrsRtpHeader::set_timestamp(uint32_t v)
{
    timestamp = v;
}

uint32_t SrsRtpHeader::get_timestamp() const
{
    return timestamp;
}

void SrsRtpHeader::set_ssrc(uint32_t v)
{
    ssrc = v;
}

uint32_t SrsRtpHeader::get_ssrc() const
{
    return ssrc;
}

void SrsRtpHeader::set_padding(bool v)
{
    padding = v;
}

void SrsRtpHeader::set_padding_length(uint8_t v)
{
    padding_length = v;
}

uint8_t SrsRtpHeader::get_padding_length() const
{
    return padding_length;
}


SrsBuffer2::SrsBuffer2(char* b, int nn)
{
    p = bytes = b;
    nb_bytes = nn;
    
    // TODO: support both little and big endian.
    srs_assert(srs_is_little_endian2());
}

SrsBuffer2::~SrsBuffer2()
{
}

char* SrsBuffer2::data()
{
    return bytes;
}

char* SrsBuffer2::head()
{
    return p;
}

int SrsBuffer2::size()
{
    return nb_bytes;
}

void SrsBuffer2::set_size(int v)
{
    nb_bytes = v;
}

int SrsBuffer2::pos()
{
    return (int)(p - bytes);
}

int SrsBuffer2::left()
{
    return nb_bytes - (int)(p - bytes);
}

bool SrsBuffer2::empty()
{
    return !bytes || (p >= bytes + nb_bytes);
}

bool SrsBuffer2::require(int required_size)
{
    srs_assert(required_size >= 0);
    
    return required_size <= nb_bytes - (p - bytes);
}

void SrsBuffer2::skip(int size)
{
    srs_assert(p);
    srs_assert(p + size >= bytes);
    srs_assert(p + size <= bytes + nb_bytes);
    
    p += size;
}

int8_t SrsBuffer2::read_1bytes()
{
    srs_assert(require(1));
    
    return (int8_t)*p++;
}

int16_t SrsBuffer2::read_2bytes()
{
    srs_assert(require(2));
    
    int16_t value;
    char* pp = (char*)&value;
    pp[1] = *p++;
    pp[0] = *p++;
    
    return value;
}

int32_t SrsBuffer2::read_3bytes()
{
    srs_assert(require(3));
    
    int32_t value = 0x00;
    char* pp = (char*)&value;
    pp[2] = *p++;
    pp[1] = *p++;
    pp[0] = *p++;
    
    return value;
}

int32_t SrsBuffer2::read_4bytes()
{
    srs_assert(require(4));
    
    int32_t value;
    char* pp = (char*)&value;
    pp[3] = *p++;
    pp[2] = *p++;
    pp[1] = *p++;
    pp[0] = *p++;
    
    return value;
}

int64_t SrsBuffer2::read_8bytes()
{
    srs_assert(require(8));
    
    int64_t value;
    char* pp = (char*)&value;
    pp[7] = *p++;
    pp[6] = *p++;
    pp[5] = *p++;
    pp[4] = *p++;
    pp[3] = *p++;
    pp[2] = *p++;
    pp[1] = *p++;
    pp[0] = *p++;
    
    return value;
}

string SrsBuffer2::read_string(int len)
{
    srs_assert(require(len));
    
    std::string value;
    value.append(p, len);
    
    p += len;
    
    return value;
}

void SrsBuffer2::read_bytes(char* data, int size)
{
    srs_assert(require(size));
    
    memcpy(data, p, size);
    
    p += size;
}

void SrsBuffer2::write_1bytes(int8_t value)
{
    srs_assert(require(1));
    
    *p++ = value;
}

void SrsBuffer2::write_2bytes(int16_t value)
{
    srs_assert(require(2));
    
    char* pp = (char*)&value;
    *p++ = pp[1];
    *p++ = pp[0];
}

void SrsBuffer2::write_4bytes(int32_t value)
{
    srs_assert(require(4));
    
    char* pp = (char*)&value;
    *p++ = pp[3];
    *p++ = pp[2];
    *p++ = pp[1];
    *p++ = pp[0];
}

void SrsBuffer2::write_3bytes(int32_t value)
{
    srs_assert(require(3));
    
    char* pp = (char*)&value;
    *p++ = pp[2];
    *p++ = pp[1];
    *p++ = pp[0];
}

void SrsBuffer2::write_8bytes(int64_t value)
{
    srs_assert(require(8));
    
    char* pp = (char*)&value;
    *p++ = pp[7];
    *p++ = pp[6];
    *p++ = pp[5];
    *p++ = pp[4];
    *p++ = pp[3];
    *p++ = pp[2];
    *p++ = pp[1];
    *p++ = pp[0];
}

void SrsBuffer2::write_string(string value)
{
    srs_assert(require((int)value.length()));
    
    memcpy(p, value.data(), value.length());
    p += value.length();
}

void SrsBuffer2::write_bytes(char* data, int size)
{
    srs_assert(require(size));
    
    memcpy(p, data, size);
    p += size;
}

SrsRtpPacket2::SrsRtpPacket2()
{
    padding = 0;
    payload = NULL;
    original_bytes = NULL;

    cache_raw = new SrsRtpRawPayload();
    cache_payload = 0;
}

SrsRtpPacket2::~SrsRtpPacket2()
{
    // We may use the cache as payload.
    if (payload == cache_raw) {
        payload = NULL;
    }

    srs_freep(payload);
    srs_freep(cache_raw);
    srs_freepa(original_bytes);
}

void SrsRtpPacket2::set_padding(int size)
{
    rtp_header.set_padding(size > 0);
    rtp_header.set_padding_length(size);
    if (cache_payload) {
        cache_payload += size - padding;
    }
    padding = size;
}

void SrsRtpPacket2::add_padding(int size)
{
    rtp_header.set_padding(padding + size > 0);
    rtp_header.set_padding_length(rtp_header.get_padding_length() + size);
    if (cache_payload) {
        cache_payload += size;
    }
    padding += size;
}

void SrsRtpPacket2::reset()
{
    rtp_header.reset();
    padding = 0;
    cache_payload = 0;

    // We may use the cache as payload.
    if (payload == cache_raw) {
        payload = NULL;
    }
    srs_freep(payload);
}

SrsRtpRawPayload* SrsRtpPacket2::reuse_raw()
{
    payload = cache_raw;
    return cache_raw;
}


int SrsRtpPacket2::nb_bytes()
{
    if (!cache_payload) {
        cache_payload = rtp_header.nb_bytes() + (payload? payload->nb_bytes():0) + padding;
    }
    return cache_payload;
}

int SrsRtpPacket2::encode(SrsBuffer2* buf)
{
    int err = 0;

    if ((err = rtp_header.encode(buf)) != 0) {
        return -1;
    }

    if (payload && (err = payload->encode(buf)) != 0) {
        return -1;
    }

    if (padding > 0) {
        if (!buf->require(padding)) {
            return -1;
        }
        memset(buf->data() + buf->pos(), padding, padding);
        buf->skip(padding);
    }

    return err;
}

int SrsRtpPacket2::decode(SrsBuffer2* buf)
{
    int err = 0;

    if ((err = rtp_header.decode(buf)) != 0) {
        return -1;
    }

    // We must skip the padding bytes before parsing payload.
    padding = rtp_header.get_padding_length();
    if (!buf->require(padding)) {
        return -1;
    }
    buf->set_size(buf->size() - padding);


    // By default, we always use the RAW payload.
    if (!payload) {
        payload = reuse_raw();
    }

    if ((err = payload->decode(buf)) != 0) {
        return -1;
    }

    return err;
}


SrsRtpRawPayload::SrsRtpRawPayload()
{
    payload = NULL;
    nn_payload = 0;
}

SrsRtpRawPayload::~SrsRtpRawPayload()
{
}

int SrsRtpRawPayload::nb_bytes()
{
    return nn_payload;
}

int SrsRtpRawPayload::encode(SrsBuffer2* buf)
{
    if (nn_payload <= 0) {
        return 0;
    }

    if (!buf->require(nn_payload)) {
        return -1;
    }

    buf->write_bytes(payload, nn_payload);

    return 0;
}

int SrsRtpRawPayload::decode(SrsBuffer2* buf)
{
    if (buf->empty()) {
        return 0;
    }

    payload = buf->head();
    nn_payload = buf->left();

    return 0;
}

SrsPsStreamClient::SrsPsStreamClient(std::string id, bool a, bool k)
{
    audio_enable = a;
    wait_first_keyframe = k;
    channel_id = id;
    first_keyframe_flag = false;
    blackhole_addr = NULL;
    seq = 0;
    pack_index  = 0;
    nfd = 0;
}

SrsPsStreamClient::~SrsPsStreamClient()
{
}

bool SrsPsStreamClient::can_send_ps_av_packet(){
    if (!wait_first_keyframe)
        return true;
    
    if (first_keyframe_flag)
       return true;

    return false;
}

int64_t  SrsPsStreamClient::parse_ps_timestamp(const uint8_t* p)
{
	unsigned long b;
	//total 33 bits
	unsigned long val, val2, val3;

	//1st byte, 5、6、7 bit
	b = *p++;
	val = (b & 0x0e);

	//2 byte, all bit 
	b = (*(p++)) << 8;
    //3 bytes 1--7 bit
	b += *(p++);
	val2 = (b & 0xfffe) >> 1;
	
	//4 byte, all bit
	b = (*(p++)) << 8;
    //5 byte 1--7 bit
	b += *(p++);
	val3 = (b & 0xfffe) >> 1;

    //<32--val--30> <29----val2----15> <14----val3----0>
	val = (val << 29) | (val2 << 15) | val3;
	return val;
}

void SrsPsStreamClient::read_ps_file(std::string filename, char**msg, long *size)
{
    char* text;
    FILE *pf = fopen(filename.c_str(),"r");
    fseek(pf,0,SEEK_END);
    long lSize = ftell(pf);
    text = (char*)malloc(lSize);
    rewind(pf); 
    fread(text,sizeof(char),lSize,pf);

    *size = lSize;
    *msg = text;
}

int  SrsPsStreamClient::init_sock(std::string host, int port, int start_port)
{
    blackhole_addr = new sockaddr_in();
    blackhole_addr->sin_family = AF_INET;
    blackhole_addr->sin_addr.s_addr = inet_addr(host.c_str());
    blackhole_addr->sin_port = htons(port);

    int sock;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }

    int n = 1;
    int r0 = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof(n));
    assert(!r0);

    if (start_port != 0){
        sockaddr_in addr;
        memset(&addr, 0, sizeof(sockaddr_in));

        addr.sin_family = AF_INET;
        addr.sin_port = htons(start_port+sock);
        addr.sin_addr.s_addr = INADDR_ANY;

        r0 = bind(sock, (sockaddr *)&addr, sizeof(sockaddr_in));
    }

    if ((nfd = st_netfd_open_socket(sock)) == NULL) {
        close(sock);
        return -1;
    }

    Trace("init sock=%d port=%d, nfd=%d", sock, start_port+sock, nfd);
    return 0;
}

int  SrsPsStreamClient::sendto(char *data, int size, int64_t timeout)
{
    srs_assert(data);

    return st_sendto(nfd, data, size,  
            (sockaddr*)blackhole_addr, sizeof(sockaddr_in), timeout);

}

//#define W_VIDEO_FILE
//#define W_AUDIO_FILE
//#define W_UNKONW_FILE
//#define W_PS_FILE

#define TIMEOUT (2*1000000LL)

int SrsPsStreamClient::publish_ps(char* ps_data, int ps_size, uint32_t timestamp, uint32_t ssrc)
{
    while(true){
        if (!ps_data || !ps_size){
            Error("ps data is null");
            break;
        }
        on_ps_stream(ps_data, ps_size, timestamp, ssrc);
    }
}


int SrsPsStreamClient::send_rtp_packet(char* payload, int payload_len, int pack_index, uint16_t seq, uint32_t ssrc, bool maker)
{
    SrsRtpPacket2 rtp;
    rtp.rtp_header.set_ssrc(ssrc);
    rtp.rtp_header.set_payload_type(96);
    rtp.rtp_header.set_sequence(seq);
    rtp.rtp_header.set_timestamp(3600*pack_index);
    rtp.payload = new SrsRtpRawPayload();
    rtp.payload->payload = payload;
    rtp.payload->nn_payload = payload_len;

    rtp.rtp_header.set_marker(maker);

    char *base = new char[1500];
    SrsBuffer2 stream((char*)base, 1500);
    rtp.encode(&stream);
    
    int ret = sendto(stream.data(), stream.pos(), TIMEOUT);
    
    #ifdef W_PS_FILE           
            if (!ps_fw.is_open()) {
                    std::string filename = "test_ps.mpg";
                    ps_fw.open(filename.c_str());
            }
            ps_fw.write(stream.data(), stream.pos(), NULL);             
    #endif
    srs_freepa(base);

    return ret;
}

int SrsPsStreamClient::on_ps_stream(char* ps_data, int ps_size, uint32_t timestamp, uint32_t ssrc)
{
    int err = 0;
    int complete_len = 0;
    int incomplete_len = ps_size;
    char *next_ps_pack = ps_data;

    SrsSimpleStream2 ps_packet_stream;
    uint64_t audio_pts = 0;
    uint64_t video_pts = 0;
    int pse_index = 0;
 

	while(incomplete_len >= sizeof(SrsPsPacketStartCode))
    {
    	if (next_ps_pack
			&& next_ps_pack[0] == (char)0x00
			&& next_ps_pack[1] == (char)0x00
			&& next_ps_pack[2] == (char)0x01
			&& next_ps_pack[3] == (char)0xBA)
		{
            //Trace("BA====================");
            //ps header 
            SrsPsPacketHeader *head = (SrsPsPacketHeader *)next_ps_pack;
            unsigned char pack_stuffing_length = head->stuffing_length & 0x07;
           
            if (ps_packet_stream.length() > 0){
                //Trace("ps packet=%u", ps_packet_stream.length());
                int len = ps_packet_stream.length();
                int count = len / 1400;
                bool maker = false;
                for (int i = 0; i < count; i++){

                    if ((i+1)*1400 == len)
                        maker = true;

                    char *payload = ps_packet_stream.bytes() + i * 1400;
                    int payload_len = 1400;

                    send_rtp_packet(payload, payload_len, pack_index, seq, ssrc, maker);
                    seq++;
                }

                int unlen = len - count*1400;

                if (unlen > 0){

                    char *payload =  ps_packet_stream.bytes() + count*1400;
                    int payload_len = unlen;

                    send_rtp_packet(payload, payload_len, pack_index, seq, ssrc, true);
                    seq++;
                }
                pack_index++;
                st_usleep(38*1000);
                ps_packet_stream.erase(ps_packet_stream.length());
            }
             
            ps_packet_stream.append(next_ps_pack, sizeof(SrsPsPacketHeader) + pack_stuffing_length);

            next_ps_pack = next_ps_pack + sizeof(SrsPsPacketHeader) + pack_stuffing_length;
            complete_len = complete_len + sizeof(SrsPsPacketHeader) + pack_stuffing_length;
            incomplete_len = ps_size - complete_len;
            pse_index = 0;
           
        }
        else if(next_ps_pack
			&& next_ps_pack[0] == (char)0x00
			&& next_ps_pack[1] == (char)0x00
			&& next_ps_pack[2] == (char)0x01
			&& next_ps_pack[3] == (char)0xBB)
        {
            //Trace("BB");
            //ps system header 
            SrsPsPacketBBHeader *bbhead=(SrsPsPacketBBHeader *)(next_ps_pack);
            int bbheaderlen = htons(bbhead->length);

            ps_packet_stream.append(next_ps_pack, sizeof(SrsPsPacketBBHeader) + bbheaderlen);

            next_ps_pack = next_ps_pack + sizeof(SrsPsPacketBBHeader) + bbheaderlen;
            complete_len = complete_len + sizeof(SrsPsPacketBBHeader) + bbheaderlen;
            incomplete_len = ps_size - complete_len;

            first_keyframe_flag = true;
        }
        else if(next_ps_pack
			&& next_ps_pack[0] == (char)0x00
			&& next_ps_pack[1] == (char)0x00
			&& next_ps_pack[2] == (char)0x01
			&& next_ps_pack[3] == (char)0xBC)
        {
            //Trace("BC");
            //program stream map 

		    SrsPsMapPacket* psmap_pack = (SrsPsMapPacket*)next_ps_pack;
          
            uint16_t length = htons(psmap_pack->length);

            ps_packet_stream.append(next_ps_pack, length + sizeof(SrsPsMapPacket));

            next_ps_pack = next_ps_pack + length + sizeof(SrsPsMapPacket);
            complete_len = complete_len + length + sizeof(SrsPsMapPacket);
            incomplete_len = ps_size - complete_len;
    
        }
        else if(next_ps_pack
			&& next_ps_pack[0] == (char)0x00
			&& next_ps_pack[1] == (char)0x00
			&& next_ps_pack[2] == (char)0x01
			&& next_ps_pack[3] == (char)0xE0)
        {
            //Trace("E0");
            //pse video stream
            SrsPsePacket* pse_pack = (SrsPsePacket*)next_ps_pack;

            unsigned char pts_dts_flags = (pse_pack->info[0] & 0xF0) >> 6;
            //in a frame of data, pts is obtained from the first PSE packet
            if (pse_index == 0 && pts_dts_flags > 0) {
				video_pts = parse_ps_timestamp((unsigned char*)next_ps_pack + 9);
                //Trace("gb28181: ps stream video ts=%u pkt_ts=%u", video_pts, timestamp);
			}
            pse_index +=1;

            int packlength = htons(pse_pack->length);
            int payloadlen = packlength - 2 - 1 - pse_pack->stuffing_length;

            ps_packet_stream.append(next_ps_pack, 9 + pse_pack->stuffing_length + payloadlen);

            next_ps_pack = next_ps_pack + 9 + pse_pack->stuffing_length;
            complete_len = complete_len + 9 + pse_pack->stuffing_length;

            //video_stream.append(next_ps_pack, payloadlen);

#ifdef W_VIDEO_FILE            
            if (!video_fw.is_open()) {
                 std::string filename = "test_video_" + channel_id + ".h264";
                 video_fw.open(filename.c_str());
            }
            video_fw.write(next_ps_pack,  payloadlen, NULL);          
#endif

            next_ps_pack = next_ps_pack + payloadlen;
            complete_len = complete_len + payloadlen;
            incomplete_len = ps_size - complete_len;
        }
     	else if (next_ps_pack
			&& next_ps_pack[0] == (char)0x00
			&& next_ps_pack[1] == (char)0x00
			&& next_ps_pack[2] == (char)0x01
			&& next_ps_pack[3] == (char)0xBD)
        {
            //Trace("BD");
            //private stream 

			SrsPsePacket* pse_pack = (SrsPsePacket*)next_ps_pack;
			
            int packlength = htons(pse_pack->length);
			int payload_len = packlength - 2 - 1 - pse_pack->stuffing_length;
            
            ps_packet_stream.append(next_ps_pack,  payload_len + 9 + pse_pack->stuffing_length);

			next_ps_pack = next_ps_pack + payload_len + 9 + pse_pack->stuffing_length;
            complete_len = complete_len + (payload_len + 9 + pse_pack->stuffing_length);
            incomplete_len = ps_size - complete_len;
		}
		else if (next_ps_pack
			&& next_ps_pack[0] == (char)0x00
			&& next_ps_pack[1] == (char)0x00
			&& next_ps_pack[2] == (char)0x01
			&& next_ps_pack[3] == (char)0xC0)
        {
            //Trace("C0");
            //audio stream
            
            SrsPsePacket* pse_pack = (SrsPsePacket*)next_ps_pack;

		    unsigned char pts_dts_flags = (pse_pack->info[0] & 0xF0) >> 6;
			if (pts_dts_flags > 0 ) {
				audio_pts = parse_ps_timestamp((unsigned char*)next_ps_pack + 9);
                //Trace("gb28181: ps stream audio ts=%u pkt_ts=%u", audio_pts, timestamp);
         	}

			int packlength = htons(pse_pack->length);
			int payload_len = packlength - 2 - 1 - pse_pack->stuffing_length;

            ps_packet_stream.append(next_ps_pack, 9 + pse_pack->stuffing_length + payload_len);
            next_ps_pack = next_ps_pack + 9 + pse_pack->stuffing_length;

            //audio_stream.append(next_ps_pack, payload_len);

#ifdef W_AUDIO_FILE            
            if (!audio_fw.is_open()) {
                 std::string filename = "test_audio_" + channel_id + ".aac";
                 audio_fw.open(filename.c_str());
            }
            audio_fw.write(next_ps_pack,  payload_len, NULL);          
#endif
            
			next_ps_pack = next_ps_pack + payload_len;
            complete_len = complete_len + (payload_len + 9 + pse_pack->stuffing_length);
            incomplete_len = ps_size - complete_len;

    	}
        else
        {
            

#ifdef W_UNKONW_FILE            
            if (!unknow_fw.is_open()) {
                 std::string filename = "test_unknow_" + channel_id + ".mpg";
                 unknow_fw.open(filename.c_str());
            }
            unknow_fw.write(next_ps_pack,  incomplete_len, NULL);          
#endif      
            //TODO: fixme unkonw ps data parse
            if (next_ps_pack
            && next_ps_pack[0] == (char)0x00
			&& next_ps_pack[1] == (char)0x00
			&& next_ps_pack[2] == (char)0x00
			&& next_ps_pack[3] == (char)0x01){
                //dahua's PS header may lose packets. It is sent by an RTP packet of Dahua's PS header
                //dahua rtp send format:
                //ts=1000 seq=1 mark=false payload= ps header
                //ts=1000 seq=2 mark=false payload= video
                //ts=1000 seq=3 mark=true payload= video
                //ts=1000 seq=4 mark=true payload= audio
                incomplete_len = ps_size - complete_len; 
                complete_len = complete_len + incomplete_len;
                
            }

            first_keyframe_flag = false;
            Trace("gb28181: client_id %s, unkonw ps data (%#x/%u) %02x %02x %02x %02x\n", 
                 channel_id.c_str(), ssrc, timestamp,  
                 next_ps_pack[0], next_ps_pack[1], next_ps_pack[2], next_ps_pack[3]);
        }
    }



 if (ps_packet_stream.length() > 0){
        //Trace("ps packet=%u", ps_packet_stream.length());
        int len = ps_packet_stream.length();
        int count = len / 1400;
        bool maker = false;
        for (int i = 0; i < count; i++){

            if ((i+1)*1400 == len)
                maker = true;

            char *payload = ps_packet_stream.bytes() + i * 1400;
            int payload_len = 1400;

            send_rtp_packet(payload, payload_len, pack_index, seq, ssrc, maker);
            seq++;
        }

        int unlen = len - count*1400;

        if (unlen > 0){

            char *payload =  ps_packet_stream.bytes() + count*1400;
            int payload_len = unlen;

            send_rtp_packet(payload, payload_len, pack_index, seq, ssrc, true);
            seq++;
        }
        pack_index++;
        st_usleep(30*1000);
        ps_packet_stream.erase(ps_packet_stream.length());
    }
  
    if (complete_len != ps_size){
         Trace("gb28181: client_id %s decode ps packet error (%#x/%u)! ps_size=%d  complete=%d \n", 
                     channel_id.c_str(), ssrc, timestamp, ps_size, complete_len);
    }
   
    return err;
}

SrsFileWriter2::SrsFileWriter2()
{
    fd = -1;
}

SrsFileWriter2::~SrsFileWriter2()
{
    close();
}

int SrsFileWriter2::open(string p)
{
    int ret = ERROR_SUCCESS;
    
    if (fd > 0) {
        ret = 1016;//ERROR_SYSTEM_FILE_ALREADY_OPENED;
        Error("file %s already opened. ret=%d", path.c_str(), ret);
        return ret;
    }
    
    int flags = O_CREAT|O_WRONLY|O_TRUNC;
    mode_t mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH;

    if ((fd = ::open(p.c_str(), flags, mode)) < 0) {
        ret = 1017;//ERROR_SYSTEM_FILE_OPENE;
        Error("open file %s failed. ret=%d", p.c_str(), ret);
        return ret;
    }
    
    path = p;
    
    return ret;
}

int SrsFileWriter2::open_append(string p)
{
    int ret = ERROR_SUCCESS;
    
    if (fd > 0) {
        ret = 1010; //ERROR_SYSTEM_FILE_ALREADY_OPENED;
        Error("file %s already opened. ret=%d", path.c_str(), ret);
        return ret;
    }
    
    int flags = O_APPEND|O_WRONLY;
    mode_t mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH;

    if ((fd = ::open(p.c_str(), flags, mode)) < 0) {
        ret = 1012; //ERROR_SYSTEM_FILE_OPENE;
        Error("open file %s failed. ret=%d", p.c_str(), ret);
        return ret;
    }
    
    path = p;
    
    return ret;
}

void SrsFileWriter2::close()
{
    int ret = ERROR_SUCCESS;
    
    if (fd < 0) {
        return;
    }
    
    if (::close(fd) < 0) {
        ret = 1013; //ERROR_SYSTEM_FILE_CLOSE;
        Error("close file %s failed. ret=%d", path.c_str(), ret);
        return;
    }
    fd = -1;
    
    return;
}

bool SrsFileWriter2::is_open()
{
    return fd > 0;
}

void SrsFileWriter2::seek2(int64_t offset)
{
    ::lseek(fd, (off_t)offset, SEEK_SET);
}

int64_t SrsFileWriter2::tellg()
{
    return (int64_t)::lseek(fd, 0, SEEK_CUR);
}

int SrsFileWriter2::write(void* buf, size_t count, ssize_t* pnwrite)
{
    int ret = ERROR_SUCCESS;
    
    ssize_t nwrite;
    // TODO: FIXME: use st_write.
    if ((nwrite = ::write(fd, buf, count)) < 0) {
        ret = 1014; //ERROR_SYSTEM_FILE_WRITE;
        Error("write to file %s failed. ret=%d", path.c_str(), ret);
        return ret;
    }
    
    if (pnwrite != NULL) {
        *pnwrite = nwrite;
    }
    
    return ret;
}

int SrsFileWriter2::writev(const iovec* iov, int iovcnt, ssize_t* pnwrite)
{
    int ret = ERROR_SUCCESS;
    
    ssize_t nwrite = 0;
    for (int i = 0; i < iovcnt; i++) {
        const iovec* piov = iov + i;
        ssize_t this_nwrite = 0;
        if ((ret = write(piov->iov_base, piov->iov_len, &this_nwrite)) != ERROR_SUCCESS) {
            return ret;
        }
        nwrite += this_nwrite;
    }
    
    if (pnwrite) {
        *pnwrite = nwrite;
    }
    
    return ret;
}

int SrsFileWriter2::lseek(off_t offset, int whence, off_t* seeked)
{
    off_t sk = ::lseek(fd, offset, whence);
    if (sk < 0) {
        return 1015;// ERROR_SYSTEM_FILE_SEEK;
    }
    
    if (seeked) {
        *seeked = sk;
    }
    return ERROR_SUCCESS;
}

SrsFileReader2::SrsFileReader2()
{
    fd = -1;
}

SrsFileReader2::~SrsFileReader2()
{
    close();
}

int SrsFileReader2::open(string p)
{
    int ret = 0; //ERROR_SUCCESS;
    
    if (fd > 0) {
        ret = 1000; //ERROR_SYSTEM_FILE_ALREADY_OPENED;
        Error("file %s already opened. ret=%d", path.c_str(), ret);
        return ret;
    }

    if ((fd = ::open(p.c_str(), O_RDONLY)) < 0) {
        ret = 1001; //ERROR_SYSTEM_FILE_OPENE;
        Error("open file %s failed. ret=%d", p.c_str(), ret);
        return ret;
    }
    
    path = p;
    
    return ret;
}

void SrsFileReader2::close()
{
    int ret = 0; //ERROR_SUCCESS;
    
    if (fd < 0) {
        return;
    }
    
    if (::close(fd) < 0) {
        ret = 1002; //ERROR_SYSTEM_FILE_CLOSE;
        Error("close file %s failed. ret=%d", path.c_str(), ret);
        return;
    }
    fd = -1;
    
    return;
}

bool SrsFileReader2::is_open()
{
    return fd > 0;
}

int64_t SrsFileReader2::tellg()
{
    return (int64_t)::lseek(fd, 0, SEEK_CUR);
}

void SrsFileReader2::skip(int64_t size)
{
    ::lseek(fd, (off_t)size, SEEK_CUR);
}

int64_t SrsFileReader2::seek2(int64_t offset)
{
    return (int64_t)::lseek(fd, (off_t)offset, SEEK_SET);
}

int64_t SrsFileReader2::filesize()
{
    int64_t cur = tellg();
    int64_t size = (int64_t)::lseek(fd, 0, SEEK_END);
    ::lseek(fd, (off_t)cur, SEEK_SET);
    return size;
}

int SrsFileReader2::read(void* buf, size_t count, ssize_t* pnread)
{
    int ret = 0;
    
    ssize_t nread;
    // TODO: FIXME: use st_read.
    if ((nread = ::read(fd, buf, count)) < 0) {
        ret = 1003; //ERROR_SYSTEM_FILE_READ;
        Error("read from file %s failed. ret=%d", path.c_str(), ret);
        return ret;
    }
    
    if (nread == 0) {
        ret = 1004; //ERROR_SYSTEM_FILE_EOF;
        return ret;
    }
    
    if (pnread != NULL) {
        *pnread = nread;
    }
    
    return ret;
}

int SrsFileReader2::lseek(off_t offset, int whence, off_t* seeked)
{
    off_t sk = ::lseek(fd, offset, whence);
    if (sk < 0) {
        return 1005 ;// ERROR_SYSTEM_FILE_SEEK;
    }
    
    if (seeked) {
        *seeked = sk;
    }
    return 0; //ERROR_SUCCESS;
}


SrsSimpleStream2::SrsSimpleStream2()
{
}

SrsSimpleStream2::~SrsSimpleStream2()
{
}

int SrsSimpleStream2::length()
{
    int len = (int)data.size();
    srs_assert(len >= 0);
    return len;
}

char* SrsSimpleStream2::bytes()
{
    return (length() == 0)? NULL : &data.at(0);
}

void SrsSimpleStream2::erase(int size)
{
    if (size <= 0) {
        return;
    }
    
    if (size >= length()) {
        data.clear();
        return;
    }
    
    data.erase(data.begin(), data.begin() + size);
}

void SrsSimpleStream2::append(const char* bytes, int size)
{
    if (size > 0) {
        data.insert(data.end(), bytes, bytes + size);
    }
}

void SrsSimpleStream2::append(SrsSimpleStream2* src)
{
    append(src->bytes(), src->length());
}