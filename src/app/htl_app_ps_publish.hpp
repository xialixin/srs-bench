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

#ifndef _htl_app_ps_publish_hpp
#define _htl_app_ps_publish_hpp

/*
#include <htl_app_rtmp_publish.hpp>
*/
#include <string>
#include <vector>

#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <fcntl.h>

#include <htl_core_uri.hpp>
#include <htl_os_st.hpp>

#include <htl_app_rtmp_protocol.hpp>

#define srs_assert(expression) assert(expression)

// free the p and set to NULL.
// p must be a T*.
#define srs_freep(p) \
    if (p) { \
        delete p; \
        p = NULL; \
    } \
    (void)0
// please use the freepa(T[]) to free an array,
// or the behavior is undefined.
#define srs_freepa(pa) \
    if (pa) { \
        delete[] pa; \
        pa = NULL; \
    } \
    (void)0

class SrsRtpRawPayload;
class SrsBuffer2;
class SrsFileWriter2;
class SrsPsStreamClient;

class SrsBuffer2
{
private:
    // current position at bytes.
    char* p;
    // the bytes data for buffer to read or write.
    char* bytes;
    // the total number of bytes.
    int nb_bytes;
public:
    // Create buffer with data b and size nn.
    // @remark User must free the data b.
    SrsBuffer2(char* b, int nn);
    ~SrsBuffer2();
public:
    // Get the data and head of buffer.
    //      current-bytes = head() = data() + pos()
    char* data();
    char* head();
    // Get the total size of buffer.
    //      left-bytes = size() - pos()
    int size();
    void set_size(int v);
    // Get the current buffer position.
    int pos();
    // Left bytes in buffer, total size() minus the current pos().
    int left();
    // Whether buffer is empty.
    bool empty();
    // Whether buffer is able to supply required size of bytes.
    // @remark User should check buffer by require then do read/write.
    // @remark Assert the required_size is not negative.
    bool require(int required_size);
public:
    // Skip some size.
    // @param size can be any value. positive to forward; nagetive to backward.
    // @remark to skip(pos()) to reset buffer.
    // @remark assert initialized, the data() not NULL.
    void skip(int size);
public:
    // Read 1bytes char from buffer.
    int8_t read_1bytes();
    // Read 2bytes int from buffer.
    int16_t read_2bytes();
    // Read 3bytes int from buffer.
    int32_t read_3bytes();
    // Read 4bytes int from buffer.
    int32_t read_4bytes();
    // Read 8bytes int from buffer.
    int64_t read_8bytes();
    // Read string from buffer, length specifies by param len.
    std::string read_string(int len);
    // Read bytes from buffer, length specifies by param len.
    void read_bytes(char* data, int size);
public:
    // Write 1bytes char to buffer.
    void write_1bytes(int8_t value);
    // Write 2bytes int to buffer.
    void write_2bytes(int16_t value);
    // Write 4bytes int to buffer.
    void write_4bytes(int32_t value);
    // Write 3bytes int to buffer.
    void write_3bytes(int32_t value);
    // Write 8bytes int to buffer.
    void write_8bytes(int64_t value);
    // Write string to buffer
    void write_string(std::string value);
    // Write bytes to buffer
    void write_bytes(char* data, int size);
};


const int kRtpHeaderFixedSize = 12;
const uint8_t kRtpMarker = 0x80;

class SrsRtpHeader
{
private:
    bool padding;
    uint8_t padding_length;
    bool extension;
    uint8_t cc;
    bool marker;
    uint8_t payload_type;
    uint16_t sequence;
    uint32_t timestamp;
    uint32_t ssrc;
    uint32_t csrc[15];
    uint16_t extension_length;
    // TODO:extension field.
public:
    SrsRtpHeader();
    virtual ~SrsRtpHeader();
    void reset();
public:
    virtual int decode(SrsBuffer2* buf);
    virtual int encode(SrsBuffer2* buf);
    virtual int nb_bytes();
public:
    void set_marker(bool v);
    bool get_marker() const;
    void set_payload_type(uint8_t v);
    uint8_t get_payload_type() const;
    void set_sequence(uint16_t v);
    uint16_t get_sequence() const;
    void set_timestamp(uint32_t v);
    uint32_t get_timestamp() const;
    void set_ssrc(uint32_t v);
    uint32_t get_ssrc() const;
    void set_padding(bool v);
    void set_padding_length(uint8_t v);
    uint8_t get_padding_length() const;
};

class SrsRtpPacket2
{
// RTP packet fields.
public:
    // TODO: FIXME: Rename to header.
    SrsRtpHeader rtp_header;
    // TODO: FIXME: Merge into rtp_header.
    int padding;
    SrsRtpRawPayload* payload;
// Decoder helper.
public:
    // The original bytes for decoder only, we will free it.
    char* original_bytes;
// Fast cache for performance.
private:
    // Cache frequently used payload for performance.
    SrsRtpRawPayload* cache_raw;
    int cache_payload;

public:
    SrsRtpPacket2();
    virtual ~SrsRtpPacket2();
public:
    // Set the padding of RTP packet.
    void set_padding(int size);
    // Increase the padding of RTP packet.
    void add_padding(int size);
    // Reset RTP packet.
    void reset();
    // Reuse the cached raw message as payload.
    SrsRtpRawPayload* reuse_raw();

// interface ISrsEncoder
public:
    virtual int nb_bytes();
    virtual int encode(SrsBuffer2* buf);
    virtual int decode(SrsBuffer2* buf);
};

class SrsRtpRawPayload
{
public:
    // The RAW payload, directly point to the shared memory.
    // @remark We only refer to the memory, user must free its bytes.
    char* payload;
    int nn_payload;
public: 
    SrsRtpRawPayload();
    virtual ~SrsRtpRawPayload();
// interface ISrsEncoder
public:
    virtual int nb_bytes();
    virtual int encode(SrsBuffer2* buf);
    virtual int decode(SrsBuffer2* buf);
};

class SrsFileWriter2
{
private:
    std::string path;
    int fd;
public:
    SrsFileWriter2();
    virtual ~SrsFileWriter2();
public:
    /**
     * open file writer, in truncate mode.
     * @param p a string indicates the path of file to open.
     */
    virtual int open(std::string p);
    /**
     * open file writer, in append mode.
     * @param p a string indicates the path of file to open.
     */
    virtual int open_append(std::string p);
    /**
     * close current writer.
     * @remark user can reopen again.
     */
    virtual void close();
public:
    virtual bool is_open();
    virtual void seek2(int64_t offset);
    virtual int64_t tellg();
// Interface ISrsWriteSeeker
public:
    virtual int write(void* buf, size_t count, ssize_t* pnwrite);
    virtual int writev(const iovec* iov, int iovcnt, ssize_t* pnwrite);
    virtual int lseek(off_t offset, int whence, off_t* seeked);
};


class SrsPsStreamClient
{
public:
    // gb28181 program stream struct define
    struct SrsPsPacketStartCode
    {
        uint8_t start_code[3];
        uint8_t stream_id[1];
    };

    struct SrsPsPacketHeader
    {
        SrsPsPacketStartCode start;// 4
        uint8_t info[9];
        uint8_t stuffing_length;
    };

    struct SrsPsPacketBBHeader
    {
        SrsPsPacketStartCode start;
        uint16_t    length;
    };

    struct SrsPsePacket
    {
        SrsPsPacketStartCode     start;
        uint16_t    length;
        uint8_t         info[2];
        uint8_t         stuffing_length;
    };

    struct SrsPsMapPacket
    {
        SrsPsPacketStartCode  start;
        uint16_t length;
    };

private:
    SrsFileWriter2 ps_fw;
    SrsFileWriter2 video_fw;
    SrsFileWriter2 audio_fw;
    SrsFileWriter2 unknow_fw;

    bool first_keyframe_flag;
    bool wait_first_keyframe;
    bool audio_enable;
    std::string channel_id;
    sockaddr_in* blackhole_addr;
    st_netfd_t nfd;

    uint16_t seq;
    int64_t pack_index;
public:
    SrsPsStreamClient(std::string sid, bool a, bool k);
    virtual ~SrsPsStreamClient();
private:
    bool can_send_ps_av_packet();
    int64_t parse_ps_timestamp(const uint8_t* p);
    int on_ps_stream(char* ps_data, int ps_size, uint32_t timestamp, uint32_t ssrc);
    int sendto(char *data, int size, int64_t timeout);
    int send_rtp_packet(char* data, int size, int pack_index, uint16_t seq, uint32_t ssrc, bool maker);
public:
    int publish_ps(char* ps_data, int ps_size, uint32_t timestamp, uint32_t ssrc);
    int init_sock(std::string host, int port, int start_port);
public:
    static void read_ps_file(std::string filename, char**msg, long *size);
};

class SrsFileReader2
{
private:
    std::string path;
    int fd;
public:
    SrsFileReader2();
    virtual ~SrsFileReader2();
public:
    /**
     * open file reader.
     * @param p a string indicates the path of file to open.
     */
    virtual int open(std::string p);
    /**
     * close current reader.
     * @remark user can reopen again.
     */
    virtual void close();
public:
    // TODO: FIXME: extract interface.
    virtual bool is_open();
    virtual int64_t tellg();
    virtual void skip(int64_t size);
    virtual int64_t seek2(int64_t offset);
    virtual int64_t filesize();
// Interface ISrsReadSeeker
public:
    virtual int read(void* buf, size_t count, ssize_t* pnread);
    virtual int lseek(off_t offset, int whence, off_t* seeked);
};


class SrsSimpleStream2
{
private:
    std::vector<char> data;
public:
    SrsSimpleStream2();
    virtual ~SrsSimpleStream2();
public:
    /**
     * get the length of buffer. empty if zero.
     * @remark assert length() is not negative.
     */
    virtual int length();
    /**
     * get the buffer bytes.
     * @return the bytes, NULL if empty.
     */
    virtual char* bytes();
    /**
     * erase size of bytes from begin.
     * @param size to erase size of bytes.
     *       clear if size greater than or equals to length()
     * @remark ignore size is not positive.
     */
    virtual void erase(int size);
    /**
     * append specified bytes to buffer.
     * @param size the size of bytes
     * @remark assert size is positive.
     */
    virtual void append(const char* bytes, int size);
    virtual void append(SrsSimpleStream2* src);
};


#endif
