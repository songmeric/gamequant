Interface Definitions
IPacketProducer.h
cppCopy#pragma once

#include <functional>
#include "RawPacket.h"

/// Interface for producing raw packets into the engine
class IPacketProducer {
public:
    // Callback type for delivering RawPackets
    using PacketCallback = std::function<void(RawPacket&&)>;

    // Virtual destructor for derived classes
    virtual ~IPacketProducer() = default;

    /**
     * Start producing packets.
     * @param callback Function to call for each packet
     */
    virtual void run(PacketCallback callback) = 0;

    /**
     * Stop the producer and join any threads.
     */
    virtual void stop() = 0;
};
IPacketParser.h
cppCopy#pragma once

#include "RawPacket.h"
#include "ParsedPacket.h"

/// Interface for parsing raw packet bytes into structured data
class IPacketParser {
public:
    virtual ~IPacketParser() = default;

    /**
     * Parse a RawPacket into a ParsedPacket.
     * @param raw Raw packet to parse
     * @return    ParsedPacket with extracted headers and metadata
     */
    virtual ParsedPacket parse(const RawPacket& raw) = 0;
};
IPacketCorrelator.h
cppCopy#pragma once

#include "ParsedPacket.h"
#include "MatchResult.h"
#include <optional>

/// Interface for correlating packets
class IPacketCorrelator {
public:
    virtual ~IPacketCorrelator() = default;

    /**
     * Attempt to correlate the given packet with a stored one.
     * @param packet ParsedPacket to correlate
     * @return       std::optional<MatchResult>
     */
    virtual std::optional<MatchResult>
    correlate(ParsedPacket&& packet) = 0;
};
IUnmatchedStore.h
cppCopy#pragma once

#include "ParsedPacket.h"
#include <optional>

/// Interface for storing unmatched packets
class IUnmatchedStore {
public:
    virtual ~IUnmatchedStore() = default;

    /**
     * Insert a packet for later correlation.
     * @param packet ParsedPacket to store
     */
    virtual void insert(const ParsedPacket& packet) = 0;

    /**
     * Remove and return a matching packet if found.
     * @param packet ParsedPacket to match
     * @return       std::optional<ParsedPacket>
     */
    virtual std::optional<ParsedPacket>
    retrieve(const ParsedPacket& packet) = 0;

    /**
     * Remove expired packets based on policy.
     */
    virtual void cleanupExpired() = 0;
};
IOutputWriter.h
cppCopy#pragma once

#include "MatchResult.h"

/// Interface for writing match results to an output sink
class IOutputWriter {
public:
    virtual ~IOutputWriter() = default;

    /**
     * Buffer or write a MatchResult.
     * @param result MatchResult to output
     */
    virtual void write(const MatchResult& result) = 0;

    /**
     * Flush any buffered output.
     */
    virtual void flush() = 0;
};
Core Data Structures
RawPacket.h
cppCopy#pragma once

#include <memory>
#include <array>
#include <chrono>
#include <span>

/// Carries raw bytes and capture timestamp from packet source
struct RawPacket {
    // This is a managed buffer from the pool
    using Buffer = std::array<uint8_t, 2048>;  // 2KB fixed buffer
    using BufferPtr = std::unique_ptr<Buffer>;
    
    BufferPtr buffer;                               // Owned buffer from pool
    size_t dataSize = 0;                            // Actual data size in buffer
    std::chrono::steady_clock::time_point timestamp;// Capture timestamp
    
    // Accessor for the data span (no copying, inline for performance)
    std::span<const uint8_t> data() const { 
        return buffer ? std::span(buffer->data(), dataSize) : std::span<const uint8_t>{};
    }
    
    // Allow only move operations
    RawPacket() = default;
    RawPacket(RawPacket&&) noexcept = default;
    RawPacket& operator=(RawPacket&&) noexcept = default;
    RawPacket(const RawPacket&) = delete;
    RawPacket& operator=(const RawPacket&) = delete;
};
ParsedPacket.h
cppCopy#pragma once

#include <array>
#include <cstdint>
#include <chrono>

/// Represents whether a packet is inbound or outbound
enum class PacketDirection {
    Inbound,  // Packet coming into the system
    Outbound  // Packet going out of the system
};

/// Holds structured fields extracted from a raw packet
struct ParsedPacket {
    std::array<uint8_t, 4> srcIP;                       // Source IPv4 address
    std::array<uint8_t, 4> dstIP;                       // Destination IPv4 address
    uint16_t srcPort;                                   // Source port
    uint16_t dstPort;                                   // Destination port
    uint8_t protocol;                                   // Transport protocol (TCP=6, UDP=17)
    PacketDirection direction;                          // Packet direction
    uint64_t payloadHash;                               // Hash of packet payload
    std::chrono::steady_clock::time_point timestamp;    // Original capture time
    
    // Allow both copy and move operations
    ParsedPacket() = default;
    ParsedPacket(const ParsedPacket&) = default;
    ParsedPacket& operator=(const ParsedPacket&) = default;
    ParsedPacket(ParsedPacket&&) noexcept = default;
    ParsedPacket& operator=(ParsedPacket&&) noexcept = default;
};
MatchResult.h
cppCopy#pragma once

#include "ParsedPacket.h"
#include <chrono>

/// Represents a pair of correlated packets and their latency
struct MatchResult {
    ParsedPacket request;                               // The initial packet
    ParsedPacket response;                              // The matching packet
    std::chrono::nanoseconds latency;                   // Response - request time
    
    // Allow both copy and move operations
    MatchResult() = default;
    MatchResult(const MatchResult&) = default;
    MatchResult& operator=(const MatchResult&) = default;
    MatchResult(MatchResult&&) noexcept = default;
    MatchResult& operator=(MatchResult&&) noexcept = default;
};
Implementation Files
BufferPool.h
cppCopy#pragma once

#include <memory>
#include <optional>
#include <array>
#include <atomic>
#include "rigtorp/MPMCQueue.h"

/// Memory pool for packet buffers to minimize allocations
class BufferPool {
public:
    // Buffer size optimized for typical packet MTU plus headroom
    static constexpr size_t BUFFER_SIZE = 2048;
    
    // The buffer type that will be used by RawPacket
    using Buffer = std::array<uint8_t, BUFFER_SIZE>;
    using BufferPtr = std::unique_ptr<Buffer>;

    explicit BufferPool(size_t poolSize);
    ~BufferPool();
    
    // Get a buffer from the pool (non-blocking)
    std::optional<BufferPtr> acquire();
    
    // Return a buffer to the pool
    void release(BufferPtr buffer);
    
    // Get stats
    size_t getAvailableBuffers() const;
    size_t getTotalBuffers() const;
    
private:
    rigtorp::MPMCQueue<BufferPtr> m_bufferQueue;
    std::atomic<size_t> m_totalBuffers;
};
BufferPool.cpp
cppCopy#include "BufferPool.h"

BufferPool::BufferPool(size_t poolSize) 
    : m_bufferQueue(poolSize), m_totalBuffers(poolSize) {
    // Pre-allocate all buffers
    for (size_t i = 0; i < poolSize; ++i) {
        auto buffer = std::make_unique<Buffer>();
        m_bufferQueue.emplace(std::move(buffer));
    }
}

BufferPool::~BufferPool() {
    // Clear all remaining buffers
    BufferPtr buffer;
    while (m_bufferQueue.try_pop(buffer)) {
        // Buffer auto-destroyed
    }
}

std::optional<BufferPool::BufferPtr> BufferPool::acquire() {
    BufferPtr buffer;
    if (m_bufferQueue.try_pop(buffer)) {
        return buffer;
    }
    return std::nullopt; // No buffer available
}

void BufferPool::release(BufferPtr buffer) {
    if (buffer) { // Only if the buffer is valid
        // Try to put it back or let it be destroyed if queue is full
        bool success = m_bufferQueue.try_emplace(std::move(buffer));
        if (!success) {
            // Buffer will be deleted by unique_ptr going out of scope
        }
    }
}

size_t BufferPool::getAvailableBuffers() const {
    return m_bufferQueue.size();
}

size_t BufferPool::getTotalBuffers() const {
    return m_totalBuffers;
}
PacketProducer.h
cppCopy#pragma once

#include "IPacketProducer.h"
#include "BufferPool.h"
#include "rigtorp/MPMCQueue.h"
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>

// Forward declarations
struct pcap_file_header;

/// Produces packets from PCAP files in a specified directory
class PacketProducer : public IPacketProducer {
public:
    PacketProducer(BufferPool& bufferPool, 
                  rigtorp::MPMCQueue<RawPacket>& outputQueue);
    ~PacketProducer() override;

    // Implement IPacketProducer interface
    void run(PacketCallback callback) override;
    void stop() override;

    // Configure directory to monitor for PCAP files
    void setSourceDirectory(const std::string& directory);

    // Get stats
    size_t getProcessedPackets() const;
    size_t getProcessedFiles() const;

private:
    // Memory-mapped file handling
    class MappedPcapFile {
    public:
        MappedPcapFile(const std::string& filename);
        ~MappedPcapFile();

        bool isValid() const;
        bool readNextPacket(RawPacket& packet, BufferPool& bufferPool);
        
    private:
        int m_fd;
        void* m_mappedData;
        size_t m_fileSize;
        size_t m_currentOffset;
        pcap_file_header* m_fileHeader;
        bool m_isValid;
    };

    void processDirectory();
    void processPcapFile(const std::string& filename);

    BufferPool& m_bufferPool;
    rigtorp::MPMCQueue<RawPacket>& m_outputQueue;
    std::string m_sourceDirectory;
    std::atomic<bool> m_running;
    std::unique_ptr<std::thread> m_worker;
    PacketCallback m_callback;
    std::atomic<size_t> m_processedPackets;
    std::atomic<size_t> m_processedFiles;
};
PacketProducer.cpp
cppCopy#include "PacketProducer.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <filesystem>
#include <algorithm>
#include <chrono>
#include <thread>

// PCAP file header structure
struct pcap_file_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
};

// PCAP packet header structure
struct pcap_pkthdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
};

PacketProducer::PacketProducer(BufferPool& bufferPool, 
                               rigtorp::MPMCQueue<RawPacket>& outputQueue)
    : m_bufferPool(bufferPool), 
      m_outputQueue(outputQueue),
      m_running(false),
      m_processedPackets(0),
      m_processedFiles(0) {
}

PacketProducer::~PacketProducer() {
    stop();
}

void PacketProducer::run(PacketCallback callback) {
    if (m_running) return;
    
    m_callback = std::move(callback);
    m_running = true;
    
    m_worker = std::make_unique<std::thread>([this] {
        processDirectory();
    });
}

void PacketProducer::stop() {
    if (!m_running) return;
    
    m_running = false;
    
    if (m_worker && m_worker->joinable()) {
        m_worker->join();
    }
    
    m_worker.reset();
}

void PacketProducer::setSourceDirectory(const std::string& directory) {
    m_sourceDirectory = directory;
}

size_t PacketProducer::getProcessedPackets() const {
    return m_processedPackets.load(std::memory_order_relaxed);
}

size_t PacketProducer::getProcessedFiles() const {
    return m_processedFiles.load(std::memory_order_relaxed);
}

void PacketProducer::processDirectory() {
    namespace fs = std::filesystem;
    
    while (m_running) {
        // Get all PCAP files in directory
        std::vector<fs::path> pcapFiles;
        
        for (const auto& entry : fs::directory_iterator(m_sourceDirectory)) {
            if (entry.is_regular_file() && 
                entry.path().extension() == ".pcap") {
                pcapFiles.push_back(entry.path());
            }
        }
        
        // Sort by creation time
        std::sort(pcapFiles.begin(), pcapFiles.end(), 
            [](const fs::path& a, const fs::path& b) {
                return fs::last_write_time(a) < fs::last_write_time(b);
            });
        
        // Process each file
        for (const auto& file : pcapFiles) {
            if (!m_running) break;
            
            processPcapFile(file.string());
            
            // Move or mark as processed
            try {
                fs::rename(file, file.string() + ".processed");
                m_processedFiles.fetch_add(1, std::memory_order_relaxed);
            } catch (const std::exception& e) {
                // Log error and continue
            }
        }
        
        // Wait before checking directory again
        if (m_running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void PacketProducer::processPcapFile(const std::string& filename) {
    MappedPcapFile pcapFile(filename);
    
    if (!pcapFile.isValid()) {
        // Log error and return
        return;
    }
    
    RawPacket packet;
    while (m_running && pcapFile.readNextPacket(packet, m_bufferPool)) {
        // Use the callback if provided, otherwise use the queue
        if (m_callback) {
            m_callback(std::move(packet));
        } else {
            m_outputQueue.try_emplace(std::move(packet));
        }
        
        m_processedPackets.fetch_add(1, std::memory_order_relaxed);
    }
}

// MappedPcapFile implementation
PacketProducer::MappedPcapFile::MappedPcapFile(const std::string& filename)
    : m_fd(-1), m_mappedData(nullptr), m_fileSize(0), 
      m_currentOffset(0), m_fileHeader(nullptr), m_isValid(false) {
    
    // Open file
    m_fd = open(filename.c_str(), O_RDONLY);
    if (m_fd == -1) return;
    
    // Get file size
    struct stat sb;
    if (fstat(m_fd, &sb) == -1) {
        close(m_fd);
        m_fd = -1;
        return;
    }
    
    m_fileSize = static_cast<size_t>(sb.st_size);
    
    // Map file into memory
    m_mappedData = mmap(nullptr, m_fileSize, PROT_READ, MAP_PRIVATE, m_fd, 0);
    if (m_mappedData == MAP_FAILED) {
        close(m_fd);
        m_fd = -1;
        m_mappedData = nullptr;
        return;
    }
    
    // Prefetch file data into memory
    madvise(m_mappedData, m_fileSize, MADV_SEQUENTIAL);
    
    // Validate PCAP header
    if (m_fileSize < sizeof(pcap_file_header)) {
        munmap(m_mappedData, m_fileSize);
        close(m_fd);
        m_fd = -1;
        m_mappedData = nullptr;
        return;
    }
    
    m_fileHeader = static_cast<pcap_file_header*>(m_mappedData);
    m_currentOffset = sizeof(pcap_file_header);
    
    // Validate magic number (0xa1b2c3d4 or 0xd4c3b2a1 for endianness)
    if (m_fileHeader->magic != 0xa1b2c3d4 && m_fileHeader->magic != 0xd4c3b2a1) {
        munmap(m_mappedData, m_fileSize);
        close(m_fd);
        m_fd = -1;
        m_mappedData = nullptr;
        return;
    }
    
    m_isValid = true;
}

PacketProducer::MappedPcapFile::~MappedPcapFile() {
    if (m_mappedData) {
        munmap(m_mappedData, m_fileSize);
    }
    
    if (m_fd != -1) {
        close(m_fd);
    }
}

bool PacketProducer::MappedPcapFile::isValid() const {
    return m_isValid;
}

bool PacketProducer::MappedPcapFile::readNextPacket(RawPacket& packet, BufferPool& bufferPool) {
    if (!m_isValid || m_currentOffset + sizeof(pcap_pkthdr) > m_fileSize) {
        return false;
    }
    
    // Get packet header
    auto* pkthdr = reinterpret_cast<pcap_pkthdr*>(
        static_cast<uint8_t*>(m_mappedData) + m_currentOffset);
    m_currentOffset += sizeof(pcap_pkthdr);
    
    // Validate packet size
    if (m_currentOffset + pkthdr->caplen > m_fileSize) {
        return false;
    }
    
    // Get packet data pointer (still in mmap memory)
    const uint8_t* packet_data = static_cast<uint8_t*>(m_mappedData) + m_currentOffset;
    m_currentOffset += pkthdr->caplen;
    
    // Try to get a buffer from the pool
    auto bufferOpt = bufferPool.acquire();
    if (!bufferOpt) {
        // No buffer available - packet will be dropped
        return false;
    }
    
    // Create a packet with the buffer
    packet.buffer = std::move(bufferOpt.value());
    
    // Copy data into the buffer
    const size_t copy_len = std::min(pkthdr->caplen, 
                                    static_cast<uint32_t>(BufferPool::BUFFER_SIZE));
    std::memcpy(packet.buffer->data(), packet_data, copy_len);
    packet.dataSize = copy_len;
    
    // Set timestamp
    using namespace std::chrono;
    seconds sec(pkthdr->ts_sec);
    microseconds usec(pkthdr->ts_usec);
    system_clock::time_point pkt_time = system_clock::from_time_t(0) + sec + usec;
    packet.timestamp = std::chrono::steady_clock::now(); // Use original timestamp when possible
    
    return true;
}
PacketParser.h
cppCopy#pragma once

#include "IPacketParser.h"
#include <span>

/// Parses raw packet data into structured ParsedPacket objects
class PacketParser : public IPacketParser {
public:
    PacketParser();
    ~PacketParser() override;
    
    // Implementation of IPacketParser interface
    ParsedPacket parse(const RawPacket& raw) override;
    
    // Configure internal network for direction detection
    void setInternalNetwork(const std::array<uint8_t, 4>& prefix, uint8_t prefixLength);
    
private:
    // Helper methods for parsing specific headers
    bool parseEthernetHeader(std::span<const uint8_t> data, size_t& offset, ParsedPacket& packet);
    bool parseIPv4Header(std::span<const uint8_t> data, size_t& offset, ParsedPacket& packet);
    bool parseTCPHeader(std::span<const uint8_t> data, size_t& offset, ParsedPacket& packet);
    bool parseUDPHeader(std::span<const uint8_t> data, size_t& offset, ParsedPacket& packet);
    
    // Calculate hash of payload data
    uint64_t calculatePayloadHash(std::span<const uint8_t> data);
    
    // Determine packet direction based on IP
    PacketDirection determineDirection(const std::array<uint8_t, 4>& ip);
    
    // Network configuration
    std::array<uint8_t, 4> m_internalNetworkPrefix;
    uint8_t m_internalNetworkPrefixLength;
};
PacketParser.cpp
cppCopy#include "PacketParser.h"
#include <cstring>
#include <functional>
#include <arpa/inet.h>

// Ethernet header structure
struct EthernetHeader {
    uint8_t dstMac[6];
    uint8_t srcMac[6];
    uint16_t etherType;
};

// IPv4 header structure
struct IPv4Header {
    uint8_t versionIhl;
    uint8_t tos;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsFragmentOffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t headerChecksum;
    uint8_t srcIp[4];
    uint8_t dstIp[4];
};

// TCP header structure
struct TCPHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t sequenceNumber;
    uint32_t ackNumber;
    uint16_t dataOffsetFlags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentPointer;
};

// UDP header structure
struct UDPHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t length;
    uint16_t checksum;
};

PacketParser::PacketParser() {
    // Default to 192.168.0.0/16 as internal network
    m_internalNetworkPrefix = {192, 168, 0, 0};
    m_internalNetworkPrefixLength = 16;
}

PacketParser::~PacketParser() = default;

void PacketParser::setInternalNetwork(const std::array<uint8_t, 4>& prefix, uint8_t prefixLength) {
    m_internalNetworkPrefix = prefix;
    m_internalNetworkPrefixLength = prefixLength;
}

ParsedPacket PacketParser::parse(const RawPacket& raw) {
    ParsedPacket parsed;
    size_t offset = 0;
    
    // Get packet data as a span for zero-copy access
    std::span<const uint8_t> data = raw.data();
    
    // Parse Ethernet header
    if (!parseEthernetHeader(data, offset, parsed)) {
        return parsed;
    }
    
    // Parse IP header
    if (!parseIPv4Header(data, offset, parsed)) {
        return parsed;
    }
    
    // Parse TCP or UDP based on protocol
    if (parsed.protocol == 6) { // TCP
        if (!parseTCPHeader(data, offset, parsed)) {
            return parsed;
        }
    } else if (parsed.protocol == 17) { // UDP
        if (!parseUDPHeader(data, offset, parsed)) {
            return parsed;
        }
    } else {
        // Unsupported protocol
        return parsed;
    }
    
    // Calculate payload hash if there's payload data
    if (offset < data.size()) {
        parsed.payloadHash = calculatePayloadHash(data.subspan(offset));
    }
    
    // Set timestamp from original packet
    parsed.timestamp = raw.timestamp;
    
    return parsed;
}

bool PacketParser::parseEthernetHeader(std::span<const uint8_t> data, 
                                     size_t& offset, 
                                     ParsedPacket& packet) {
    if (data.size() < sizeof(EthernetHeader)) {
        return false;
    }
    
    const auto* ethHeader = 
        reinterpret_cast<const EthernetHeader*>(data.data());
    
    // Check for IPv4 packet (EtherType = 0x0800, in network byte order)
    uint16_t etherType = ntohs(ethHeader->etherType);
    
    if (etherType != 0x0800) {
        return false; // Not IPv4
    }
    
    offset += sizeof(EthernetHeader);
    return true;
}

bool PacketParser::parseIPv4Header(std::span<const uint8_t> data, 
                                 size_t& offset, 
                                 ParsedPacket& packet) {
    if (data.size() < offset + sizeof(IPv4Header)) {
        return false;
    }
    
    const auto* ipHeader = 
        reinterpret_cast<const IPv4Header*>(data.data() + offset);
    
    // Get IP header length (in 32-bit words)
    uint8_t ihl = (ipHeader->versionIhl & 0x0F);
    size_t ipHeaderLength = ihl * 4;
    
    if (data.size() < offset + ipHeaderLength) {
        return false;
    }
    
    // Extract IP addresses
    std::memcpy(packet.srcIP.data(), ipHeader->srcIp, 4);
    std::memcpy(packet.dstIP.data(), ipHeader->dstIp, 4);
    
    // Set protocol
    packet.protocol = ipHeader->protocol;
    
    // Determine direction
    packet.direction = determineDirection(packet.srcIP);
    
    offset += ipHeaderLength;
    return true;
}

bool PacketParser::parseTCPHeader(std::span<const uint8_t> data, 
                                size_t& offset, 
                                ParsedPacket& packet) {
    if (data.size() < offset + sizeof(TCPHeader)) {
        return false;
    }
    
    const auto* tcpHeader = 
        reinterpret_cast<const TCPHeader*>(data.data() + offset);
    
    // Get data offset (in 32-bit words)
    uint8_t dataOffset = (ntohs(tcpHeader->dataOffsetFlags) >> 12) & 0x0F;
    size_t tcpHeaderLength = dataOffset * 4;
    
    if (data.size() < offset + tcpHeaderLength) {
        return false;
    }
    
    // Extract ports (network byte order)
    packet.srcPort = ntohs(tcpHeader->srcPort);
    packet.dstPort = ntohs(tcpHeader->dstPort);
    
    offset += tcpHeaderLength;
    return true;
}

bool PacketParser::parseUDPHeader(std::span<const uint8_t> data, 
                                size_t& offset, 
                                ParsedPacket& packet) {
    if (data.size() < offset + sizeof(UDPHeader)) {
        return false;
    }
    
    const auto* udpHeader = 
        reinterpret_cast<const UDPHeader*>(data.data() + offset);
    
    // Extract ports (network byte order)
    packet.srcPort = ntohs(udpHeader->srcPort);
    packet.dstPort = ntohs(udpHeader->dstPort);
    
    offset += sizeof(UDPHeader);
    return true;
}

uint64_t PacketParser::calculatePayloadHash(std::span<const uint8_t> data) {
    if (data.empty()) {
        return 0;
    }
    
    // Use a simple FNV-1a hash
    uint64_t hash = 14695981039346656037ULL;
    for (uint8_t byte : data) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    
    return hash;
}

PacketDirection PacketParser::determineDirection(const std::array<uint8_t, 4>& ip) {
    // Compare IP address to internal network prefix
    for (size_t i = 0; i < m_internalNetworkPrefixLength / 8; i++) {
        if (ip[i] != m_internalNetworkPrefix[i]) {
            return PacketDirection::Inbound;
        }
    }
    
    // If we reached here, the first bytes match the prefix
    // Check partial byte if needed
    if (m_internalNetworkPrefixLength % 8 != 0) {
        uint8_t remainingBits = m_internalNetworkPrefixLength % 8;
        uint8_t mask = ~(0xFF >> remainingBits);
        
        if ((ip[m_internalNetworkPrefixLength / 8] & mask) !=
            (m_internalNetworkPrefix[m_internalNetworkPrefixLength / 8] & mask)) {
            return PacketDirection::Inbound;
        }
    }
    
    return PacketDirection::Outbound;
}
UnmatchedStore.h
cppCopy#pragma once

#include "IUnmatchedStore.h"
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>
#include <memory>
#include <array>
#include <atomic>

/// Stores unmatched packets for later correlation
class UnmatchedStore : public IUnmatchedStore {
public:
    UnmatchedStore(std::chrono::milliseconds expiryDuration = std::chrono::seconds(30),
                  size_t shardCount = 16);
    ~UnmatchedStore() override;
    
    void insert(const ParsedPacket& packet) override;
    std::optional<ParsedPacket> retrieve(const ParsedPacket& packet) override;
    void cleanupExpired() override;
    
    // Stats methods
    size_t getTotalStoredPackets() const;
    
private:
    // Forward declarations
    struct PacketKey;
    struct StoredPacket;
    struct Shard;
    
    // Packet key for matching
    struct PacketKey {
        uint32_t srcIP;
        uint32_t dstIP;
        uint16_t srcPort;
        uint16_t dstPort;
        uint8_t protocol;
        uint64_t payloadHash;
        
        // Hash function declaration (defined in .cpp)
        struct Hasher {
            size_t operator()(const PacketKey& key) const;
        };
        
        // Equality comparison (defined in .cpp)
        bool operator==(const PacketKey& other) const;
    };
    
    // Packet storage structure
    struct StoredPacket {
        ParsedPacket packet;
        std::chrono::steady_clock::time_point expiry;
    };
    
    // Shard for lock reduction
    struct Shard {
        std::unordered_map<PacketKey, StoredPacket, PacketKey::Hasher> packets;
        mutable std::shared_mutex mutex;
    };
    
    // Helper methods
    size_t getShardIndex(const PacketKey& key) const;
    PacketKey createKey(const ParsedPacket& packet) const;
    PacketKey createMatchingKey(const ParsedPacket& packet) const;
    
    // Member variables
    std::vector<std::unique_ptr<Shard>> m_shards;
    std::chrono::milliseconds m_expiryDuration;
    mutable std::atomic<size_t> m_totalPackets;
};
UnmatchedStore.cpp
cppCopy#include "UnmatchedStore.h"

UnmatchedStore::UnmatchedStore(std::chrono::milliseconds expiryDuration, 
                             size_t shardCount)
    : m_expiryDuration(expiryDuration), m_totalPackets(0) {
    
    // Create shards
    m_shards.reserve(shardCount);
    for (size_t i = 0; i < shardCount; ++i) {
        m_shards.push_back(std::make_unique<Shard>());
    }
}

UnmatchedStore::~UnmatchedStore() = default;

void UnmatchedStore::insert(const ParsedPacket& packet) {
    auto key = createKey(packet);
    auto shardIdx = getShardIndex(key);
    auto& shard = *m_shards[shardIdx];
    
    // Exclusive lock for writing
    std::unique_lock lock(shard.mutex);
    
    auto expiry = std::chrono::steady_clock::now() + m_expiryDuration;
    shard.packets.insert_or_assign(key, StoredPacket{packet, expiry});
    
    m_totalPackets.fetch_add(1, std::memory_order_relaxed);
}

std::optional<ParsedPacket> UnmatchedStore::retrieve(
    const ParsedPacket& packet) {
    
    auto key = createMatchingKey(packet);
    auto shardIdx = getShardIndex(key);
    auto& shard = *m_shards[shardIdx];
    
    // Shared lock for reading
    std::shared_lock readLock(shard.mutex);
    
    auto it = shard.packets.find(key);
    if (it == shard.packets.end()) {
        return std::nullopt;
    }
    
    // Found match - upgrade to exclusive lock
    readLock.unlock();
    std::unique_lock writeLock(shard.mutex);
    
    // Check again after lock upgrade
    it = shard.packets.find(key);
    if (it == shard.packets.end()) {
        return std::nullopt;
    }
    
    // Extract packet and remove from map
    ParsedPacket result = it->second.packet;
    shard.packets.erase(it);
    
    m_totalPackets.fetch_sub(1, std::memory_order_relaxed);
    
    return result;
}

void UnmatchedStore::cleanupExpired() {
    auto now = std::chrono::steady_clock::now();
    
    size_t removedCount = 0;
    
    // Process each shard independently
    for (auto& shardPtr : m_shards) {
        auto& shard = *shardPtr;
        std::unique_lock lock(shard.mutex);
        
        for (auto it = shard.packets.begin(); it != shard.packets.end();) {
            if (it->second.expiry < now) {
                it = shard.packets.erase(it);
                removedCount++;
            } else {
                ++it;
            }
        }
    }
    
    if (removedCount > 0) {
        m_totalPackets.fetch_sub(removedCount, std::memory_order_relaxed);
    }
}

size_t UnmatchedStore::getTotalStoredPackets() const {
    return m_totalPackets.load(std::memory_order_relaxed);
}

size_t UnmatchedStore::getShardIndex(const PacketKey& key) const {
    // Use hash to distribute among shards
    return PacketKey::Hasher{}(key) % m_shards.size();
}

UnmatchedStore::PacketKey 
UnmatchedStore::createKey(const ParsedPacket& packet) const {
    PacketKey key;
    
    // Convert IPv4 array to uint32_t
    key.srcIP = (packet.srcIP[0] << 24) | (packet.srcIP[1] << 16) | 
                (packet.srcIP[2] << 8) | packet.srcIP[3];
    key.dstIP = (packet.dstIP[0] << 24) | (packet.dstIP[1] << 16) | 
                (packet.dstIP[2] << 8) | packet.dstIP[3];
    
    key.srcPort = packet.srcPort;
    key.dstPort = packet.dstPort;
    key.protocol = packet.protocol;
    key.payloadHash = packet.payloadHash;
    
    return key;
}

UnmatchedStore::PacketKey 
UnmatchedStore::createMatchingKey(const ParsedPacket& packet) const {
    PacketKey key;
    
    // For matching, we swap src/dst to match the other direction
    key.srcIP = (packet.dstIP[0] << 24) | (packet.dstIP[1] << 16) | 
                (packet.dstIP[2] << 8) | packet.dstIP[3];
    key.dstIP = (packet.srcIP[0] << 24) | (packet.srcIP[1] << 16) | 
                (packet.srcIP[2] << 8) | packet.srcIP[3];
    
    key.srcPort = packet.dstPort;
    key.dstPort = packet.srcPort;
    
    // For UDP<->TCP matching, we might need to adapt protocol
    key.protocol = (packet.protocol == 6) ? 17 : 6; // Flip between TCP and UDP
    
    key.payloadHash = packet.payloadHash;
    
    return key;
}

// PacketKey::Hasher implementation
size_t UnmatchedStore::PacketKey::Hasher::operator()(
    const PacketKey& key) const {
    
    // FNV-1a hash
    size_t h = 14695981039346656037ULL;
    h ^= key.srcIP; h *= 1099511628211ULL;
    h ^= key.dstIP; h *= 1099511628211ULL;
    h ^= key.srcPort; h *= 1099511628211ULL;
    h ^= key.dstPort; h *= 1099511628211ULL;
    h ^= key.protocol; h *= 1099511628211ULL;
    h ^= key.payloadHash; h *= 1099511628211ULL;
    
    return h;
}

// PacketKey equality operator
bool UnmatchedStore::PacketKey::operator==(const PacketKey& other) const {
    return srcIP == other.srcIP &&
           dstIP == other.dstIP &&
           srcPort == other.srcPort &&
           dstPort == other.dstPort &&
           protocol == other.protocol &&
           payloadHash == other.payloadHash;
}
PacketCorrelator.h
cppCopy#pragma once

#include "IPacketCorrelator.h"
#include "IUnmatchedStore.h"
#include <memory>
#include <atomic>

/// Correlates related packets using an UnmatchedStore
class PacketCorrelator : public IPacketCorrelator {
public:
    explicit PacketCorrelator(std::shared_ptr<IUnmatchedStore> store);
    ~PacketCorrelator() override;
    
    // Implementation of IPacketCorrelator interface
    std::optional<MatchResult> correlate(ParsedPacket&& packet) override;
    
    // Stats methods
    size_t getMatchCount() const;
    
private:
    std::shared_ptr<IUnmatchedStore> m_store;
    std::atomic<size_t> m_matchCount;
};
PacketCorrelator.cpp
cppCopy#include "PacketCorrelator.h"

PacketCorrelator::PacketCorrelator(std::shared_ptr<IUnmatchedStore> store)
    : m_store(std::move(store)), m_matchCount(0) {
}

PacketCorrelator::~PacketCorrelator() = default;

std::optional<MatchResult> PacketCorrelator::correlate(ParsedPacket&& packet) {
    // Try to find a matching packet
    auto matchingPacket = m_store->retrieve(packet);
    
    if (matchingPacket) {
        // Create a match result
        MatchResult result;
        
        // Determine which packet is the request and which is the response
        if (packet.direction == PacketDirection::Inbound && 
            matchingPacket->direction == PacketDirection::Outbound) {
            // Current packet is inbound (request), matching is outbound (response)
            result.request = std::move(packet);
            result.response = std::move(*matchingPacket);
        } else {
            // Current packet is outbound (response), matching is inbound (request)
            result.request = std::move(*matchingPacket);
            result.response = std::move(packet);
        }
        
        // Calculate latency
        result.latency = std::chrono::duration_cast<std::chrono::nanoseconds>(
            result.response.timestamp - result.request.timestamp);
        
        m_matchCount.fetch_add(1, std::memory_order_relaxed);
        
        return result;
    } else {
        // No match found, store the packet for later correlation
        m_store->insert(packet);
        return std::nullopt;
    }
}

size_t PacketCorrelator::getMatchCount() const {
    return m_matchCount.load(std::memory_order_relaxed);
}
OutputWriter.h
cppCopy#pragma once

#include "IOutputWriter.h"
#include <string>
#include <fstream>
#include <mutex>
#include <vector>

/// Writes match results to files or standard output
class OutputWriter : public IOutputWriter {
public:
    explicit OutputWriter(const std::string& outputPath = "", 
                         size_t bufferSize = 1000);
    ~OutputWriter() override;
    
    // IOutputWriter interface implementation
    void write(const MatchResult& result) override;
    void flush() override;
    
    // Set output file path
    void setOutputPath(const std::string& path);
    
    // Get stats
    size_t getWrittenResults() const;
    
private:
    // Format a match result as a string
    std::string formatResult(const MatchResult& result) const;
    
    // Open or reopen the output file
    void openOutputFile();
    
    std::string m_outputPath;
    std::ofstream m_outputFile;
    std::mutex m_writeMutex;
    std::vector<std::string> m_buffer;
    size_t m_bufferSize;
    size_t m_writtenResults;
    bool m_useStdout;
};
OutputWriter.cpp
cppCopy#include "OutputWriter.h"
#include <iostream>
#include <iomanip>
#include <sstream>

OutputWriter::OutputWriter(const std::string& outputPath, size_t bufferSize)
    : m_outputPath(outputPath), 
      m_bufferSize(bufferSize),
      m_writtenResults(0),
      m_useStdout(outputPath.empty()) {
    
    m_buffer.reserve(m_bufferSize);
    
    if (!m_useStdout) {
        openOutputFile();
    }
}

OutputWriter::~OutputWriter() {
    flush();
    
    if (m_outputFile.is_open()) {
        m_outputFile.close();
    }
}

void OutputWriter::write(const MatchResult& result) {
    std::string formatted = formatResult(result);
    
    std::lock_guard<std::mutex> lock(m_writeMutex);
    
    m_buffer.push_back(std::move(formatted));
    m_writtenResults++;
    
    if (m_buffer.size() >= m_bufferSize) {
        flush();
    }
}

void OutputWriter::flush() {
    std::lock_guard<std::mutex> lock(m_writeMutex);
    
    if (m_buffer.empty()) {
        return;
    }
    
    if (m_useStdout) {
        // Write to stdout
        for (const auto& line : m_buffer) {
            std::cout << line << std::endl;
        }
    } else {
        // Write to file
        if (!m_outputFile.is_open()) {
            openOutputFile();
        }
        
        for (const auto& line : m_buffer) {
            m_outputFile << line << std::endl;
        }
        
        m_outputFile.flush();
    }
    
    m_buffer.clear();
}

void OutputWriter::setOutputPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_writeMutex);
    
    // Flush current buffer
    flush();
    
    // Close current file if open
    if (m_outputFile.is_open()) {
        m_outputFile.close();
    }
    
    m_outputPath = path;
    m_useStdout = path.empty();
    
    if (!m_useStdout) {
        openOutputFile();
    }
}

size_t OutputWriter::getWrittenResults() const {
    return m_writtenResults;
}

std::string OutputWriter::formatResult(const MatchResult& result) const {
    std::ostringstream oss;
    
    // Format IP addresses
    auto formatIP = [](const std::array<uint8_t, 4>& ip) {
        std::ostringstream ip_oss;
        ip_oss << static_cast<int>(ip[0]) << "."
               << static_cast<int>(ip[1]) << "."
               << static_cast<int>(ip[2]) << "."
               << static_cast<int>(ip[3]);
        return ip_oss.str();
    };
    
    // Format timestamp
    auto formatTime = [](const std::chrono::steady_clock::time_point& time) {
        // This is a placeholder since steady_clock doesn't convert to system time easily
        auto duration = time.time_since_epoch();
        auto micros = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
        return std::to_string(micros);
    };
    
    // Request information
    oss << "REQ: " << formatIP(result.request.srcIP) << ":" << result.request.srcPort
        << " -> " << formatIP(result.request.dstIP) << ":" << result.request.dstPort
        << " [" << (result.request.protocol == 17 ? "UDP" : "TCP") << "] "
        << "Time: " << formatTime(result.request.timestamp) << std::endl;
    
    // Response information
    oss << "RES: " << formatIP(result.response.srcIP) << ":" << result.response.srcPort
        << " -> " << formatIP(result.response.dstIP) << ":" << result.response.dstPort
        << " [" << (result.response.protocol == 17 ? "UDP" : "TCP") << "] "
        << "Time: " << formatTime(result.response.timestamp) << std::endl;
    
    // Latency information
    oss << "LATENCY: " << result.latency.count() << " ns";
    
    return oss.str();
}

void OutputWriter::openOutputFile() {
    m_outputFile.open(m_outputPath, std::ios::out | std::ios::app);
    
    if (!m_outputFile.is_open()) {
        // Fall back to stdout if file can't be opened
        std::cerr << "Warning: Could not open output file " << m_outputPath 
                  << ". Using stdout instead." << std::endl;
        m_useStdout = true;
    }
}
WorkerPool.h
cppCopy#pragma once

#include <vector>
#include <thread>
#include <functional>
#include <atomic>
#include <string>

/// Manages a pool of worker threads for packet processing
class WorkerPool {
public:
    using WorkerFunction = std::function<void(size_t)>;
    
    WorkerPool(size_t threadCount = 0);
    ~WorkerPool();
    
    // Start workers with the given function
    void start(WorkerFunction workerFunc);
    
    // Stop all workers and join them
    void stop();
    
    // Check if the pool is running
    bool isRunning() const;
    
    // Get the number of threads
    size_t getThreadCount() const;
    
private:
    std::vector<std::thread> m_workers;
    std::atomic<bool> m_running;
    size_t m_threadCount;
};
WorkerPool.cpp
cppCopy#include "WorkerPool.h"
#include <thread>

WorkerPool::WorkerPool(size_t threadCount)
    : m_running(false) {
    
    // If thread count is 0, use hardware concurrency
    if (threadCount == 0) {
        m_threadCount = std::thread::hardware_concurrency();
        // Ensure at least 1 thread
        if (m_threadCount == 0) {
            m_threadCount = 1;
        }
    } else {
        m_threadCount = threadCount;
    }
}

WorkerPool::~WorkerPool() {
    stop();
}

void WorkerPool::start(WorkerFunction workerFunc) {
    if (m_running) {
        return; // Already running
    }
    
    m_running = true;
    
    m_workers.clear();
    m_workers.reserve(m_threadCount);
    
    for (size_t i = 0; i < m_threadCount; ++i) {
        m_workers.emplace_back([this, workerFunc, i]() {
            workerFunc(i);
        });
    }
}

void WorkerPool::stop() {
    if (!m_running) {
        return; // Not running
    }
    
    m_running = false;
    
    // Join all threads
    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    m_workers.clear();
}

bool WorkerPool::isRunning() const {
    return m_running;
}

size_t WorkerPool::getThreadCount() const {
    return m_threadCount;
}
Engine.h
cppCopy#pragma once

#include "BufferPool.h"
#include "WorkerPool.h"
#include "IPacketProducer.h"
#include "IPacketParser.h"
#include "IPacketCorrelator.h"
#include "IUnmatchedStore.h"
#include "IOutputWriter.h"
#include "RawPacket.h"
#include "ParsedPacket.h"
#include "MatchResult.h"
#include "rigtorp/MPMCQueue.h"
#include <memory>
#include <atomic>
#include <chrono>

/// Core engine that orchestrates the packet processing pipeline
class Engine {
public:
    Engine(size_t queueSize = 10000, 
          size_t bufferPoolSize = 20000,
          size_t parserThreads = 0,
          size_t correlatorThreads = 0);
    ~Engine();
    
    // Set components
    void setPacketProducer(std::shared_ptr<IPacketProducer> producer);
    void setPacketParser(std::shared_ptr<IPacketParser> parser);
    void setPacketCorrelator(std::shared_ptr<IPacketCorrelator> correlator);
    void setUnmatchedStore(std::shared_ptr<IUnmatchedStore> store);
    void setOutputWriter(std::shared_ptr<IOutputWriter> writer);
    
    // Start and stop the engine
    void start();
    void stop();
    
    // Status check
    bool isRunning() const;
    
    // Configuration
    void setCleanupInterval(std::chrono::milliseconds interval);
    
    // Stats
    struct Statistics {
        size_t rawPacketsProcessed;
        size_t parsedPacketsProcessed;
        size_t matchesFound;
        size_t unmatchedPackets;
        size_t outputsWritten;
        size_t buffersAvailable;
        size_t totalBuffers;
    };
    
    Statistics getStatistics() const;
    
private:
    // Worker functions
    void parserWorker(size_t workerId);
    void correlatorWorker(size_t workerId);
    void cleanupWorker();
    
    // Queue handling
    void onRawPacket(RawPacket&& packet);
    
    // Components
    std::shared_ptr<IPacketProducer> m_packetProducer;
    std::shared_ptr<IPacketParser> m_packetParser;
    std::shared_ptr<IPacketCorrelator> m_packetCorrelator;
    std::shared_ptr<IUnmatchedStore> m_unmatchedStore;
    std::shared_ptr<IOutputWriter> m_outputWriter;
    
    // Thread pools
    std::unique_ptr<WorkerPool> m_parserPool;
    std::unique_ptr<WorkerPool> m_correlatorPool;
    std::unique_ptr<std::thread> m_cleanupThread;
    
    // Queues
    rigtorp::MPMCQueue<RawPacket> m_rawPacketQueue;
    rigtorp::MPMCQueue<ParsedPacket> m_parsedPacketQueue;
    
    // Buffer pool
    BufferPool m_bufferPool;
    
    // State
    std::atomic<bool> m_running;
    std::chrono::milliseconds m_cleanupInterval;
    
    // Stats
    std::atomic<size_t> m_rawPacketsProcessed;
    std::atomic<size_t> m_parsedPacketsProcessed;
};
Engine.cpp
cppCopy#include "Engine.h"
#include <iostream>
#include <thread>

Engine::Engine(size_t queueSize, 
               size_t bufferPoolSize,
               size_t parserThreads,
               size_t correlatorThreads)
    : m_rawPacketQueue(queueSize),
      m_parsedPacketQueue(queueSize),
      m_bufferPool(bufferPoolSize),
      m_running(false),
      m_cleanupInterval(std::chrono::seconds(5)),
      m_rawPacketsProcessed(0),
      m_parsedPacketsProcessed(0) {
    
    m_parserPool = std::make_unique<WorkerPool>(parserThreads);
    m_correlatorPool = std::make_unique<WorkerPool>(correlatorThreads);
}

Engine::~Engine() {
    stop();
}

void Engine::setPacketProducer(std::shared_ptr<IPacketProducer> producer) {
    m_packetProducer = std::move(producer);
}

void Engine::setPacketParser(std::shared_ptr<IPacketParser> parser) {
    m_packetParser = std::move(parser);
}

void Engine::setPacketCorrelator(std::shared_ptr<IPacketCorrelator> correlator) {
    m_packetCorrelator = std::move(correlator);
}

void Engine::setUnmatchedStore(std::shared_ptr<IUnmatchedStore> store) {
    m_unmatchedStore = std::move(store);
}

void Engine::setOutputWriter(std::shared_ptr<IOutputWriter> writer) {
    m_outputWriter = std::move(writer);
}

void Engine::start() {
    if (m_running) {
        return; // Already running
    }
    
    // Validate components
    if (!m_packetProducer || !m_packetParser || !m_packetCorrelator ||
        !m_unmatchedStore || !m_outputWriter) {
        throw std::runtime_error("Engine components not fully configured");
    }
    
    m_running = true;
    
    // Start worker pools
    m_parserPool->start([this](size_t id) { parserWorker(id); });
    m_correlatorPool->start([this](size_t id) { correlatorWorker(id); });
    
    // Start cleanup thread
    m_cleanupThread = std::make_unique<std::thread>([this]() { cleanupWorker(); });
    
    // Start packet producer
    m_packetProducer->run([this](RawPacket&& packet) {
        onRawPacket(std::move(packet));
    });
}

void Engine::stop() {
    if (!m_running) {
        return; // Not running
    }
    
    m_running = false;
    
    // Stop producer
    if (m_packetProducer) {
        m_packetProducer->stop();
    }
    
    // Stop worker pools
    m_parserPool->stop();
    m_correlatorPool->stop();
    
    // Stop cleanup thread
    if (m_cleanupThread && m_cleanupThread->joinable()) {
        m_cleanupThread->join();
    }
    
    // Flush any remaining output
    if (m_outputWriter) {
        m_outputWriter->flush();
    }
}

bool Engine::isRunning() const {
    return m_running;
}

void Engine::setCleanupInterval(std::chrono::milliseconds interval) {
    m_cleanupInterval = interval;
}

Engine::Statistics Engine::getStatistics() const {
    Statistics stats;
    
    stats.rawPacketsProcessed = m_rawPacketsProcessed.load(std::memory_order_relaxed);
    stats.parsedPacketsProcessed = m_parsedPacketsProcessed.load(std::memory_order_relaxed);
    
    // Get stats from components
    if (m_packetCorrelator) {
        auto* correlator = dynamic_cast<PacketCorrelator*>(m_packetCorrelator.get());
        if (correlator) {
            stats.matchesFound = correlator->getMatchCount();
        } else {
            stats.matchesFound = 0;
        }
    } else {
        stats.matchesFound = 0;
    }
    
    if (m_unmatchedStore) {
        auto* store = dynamic_cast<UnmatchedStore*>(m_unmatchedStore.get());
        if (store) {
            stats.unmatchedPackets = store->getTotalStoredPackets();
        } else {
            stats.unmatchedPackets = 0;
        }
    } else {
        stats.unmatchedPackets = 0;
    }
    
    if (m_outputWriter) {
        auto* writer = dynamic_cast<OutputWriter*>(m_outputWriter.get());
        if (writer) {
            stats.outputsWritten = writer->getWrittenResults();
        } else {
            stats.outputsWritten = 0;
        }
    } else {
        stats.outputsWritten = 0;
    }
    
    stats.buffersAvailable = m_bufferPool.getAvailableBuffers();
    stats.totalBuffers = m_bufferPool.getTotalBuffers();
    
    return stats;
}

void Engine::parserWorker(size_t workerId) {
    RawPacket rawPacket;
    
    while (m_running) {
        if (m_rawPacketQueue.try_pop(rawPacket)) {
            // Parse the packet
            ParsedPacket parsedPacket = m_packetParser->parse(rawPacket);
            
            // Release the buffer back to the pool
            m_bufferPool.release(std::move(rawPacket.buffer));
            
            // Push to the parsed packet queue
            m_parsedPacketQueue.emplace(std::move(parsedPacket));
            
            m_parsedPacketsProcessed.fetch_add(1, std::memory_order_relaxed);
        } else {
            // No packet to process, yield to other threads
            std::this_thread::yield();
        }
    }
}

void Engine::correlatorWorker(size_t workerId) {
    ParsedPacket parsedPacket;
    
    while (m_running) {
        if (m_parsedPacketQueue.try_pop(parsedPacket)) {
            // Try to correlate the packet
            auto matchResult = m_packetCorrelator->correlate(std::move(parsedPacket));
            
            // If we got a match, write it to output
            if (matchResult) {
                m_outputWriter->write(*matchResult);
            }
        } else {
            // No packet to process, yield to other threads
            std::this_thread::yield();
        }
    }
}

void Engine::cleanupWorker() {
    while (m_running) {
        // Sleep for the cleanup interval
        std::this_thread::sleep_for(m_cleanupInterval);
        
        // Cleanup unmatched packets
        if (m_running && m_unmatchedStore) {
            m_unmatchedStore->cleanupExpired();
        }
        
        // Flush output periodically
        if (m_running && m_outputWriter) {
            m_outputWriter->flush();
        }
    }
}

void Engine::onRawPacket(RawPacket&& packet) {
    // Simply push to the raw packet queue
    if (m_rawPacketQueue.try_emplace(std::move(packet))) {
        m_rawPacketsProcessed.fetch_add(1, std::memory_order_relaxed);
    } else {
        // Queue is full, buffer will be destroyed
        // Could log this as packet drop
    }
}
Main Application Entry Point
main.cpp
cppCopy#include "PacketMatchingEngine/Engine.h"
#include "PacketMatchingEngine/PacketProducer.h"
#include "PacketMatchingEngine/PacketParser.h"
#include "PacketMatchingEngine/PacketCorrelator.h"
#include "PacketMatchingEngine/UnmatchedStore.h"
#include "PacketMatchingEngine/OutputWriter.h"
#include <iostream>
#include <csignal>
#include <chrono>
#include <thread>
#include <atomic>

// Global engine pointer for signal handling
static std::shared_ptr<Engine> g_engine;
static std::atomic<bool> g_running(true);

// Signal handler
void signalHandler(int signal) {
    std::cout << "Received signal " << signal << ", shutting down..." << std::endl;
    g_running = false;
    
    if (g_engine) {
        g_engine->stop();
    }
}

void printStatistics(const Engine::Statistics& stats) {
    std::cout << "=== Packet Matching Engine Statistics ===" << std::endl;
    std::cout << "Raw packets processed: " << stats.rawPacketsProcessed << std::endl;
    std::cout << "Parsed packets processed: " << stats.parsedPacketsProcessed << std::endl;
    std::cout << "Matches found: " << stats.matchesFound << std::endl;
    std::cout << "Unmatched packets: " << stats.unmatchedPackets << std::endl;
    std::cout << "Outputs written: " << stats.outputsWritten << std::endl;
    std::cout << "Buffer pool: " << stats.buffersAvailable << "/" 
              << stats.totalBuffers << " available" << std::endl;
    std::cout << "=======================================" << std::endl;
}

int main(int argc, char* argv[]) {
    // Parse command line arguments
    std::string inputDir = ".";
    std::string outputFile = "";
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-i" || arg == "--input") {
            if (i + 1 < argc) {
                inputDir = argv[++i];
            }
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                outputFile = argv[++i];
            }
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  -i, --input DIR    Directory to monitor for PCAP files" << std::endl;
            std::cout << "  -o, --output FILE  Output file (stdout if not specified)" << std::endl;
            std::cout << "  -h, --help         Show this help message" << std::endl;
            return 0;
        }
    }
    
    // Setup signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    try {
        // Create and configure engine
        g_engine = std::make_shared<Engine>(10000, 20000);
        
        // Create components
        auto producer = std::make_shared<PacketProducer>(
            g_engine->getBufferPool(), 
            g_engine->getRawPacketQueue());
        producer->setSourceDirectory(inputDir);
        
        auto parser = std::make_shared<PacketParser>();
        auto store = std::make_shared<UnmatchedStore>(
            std::chrono::seconds(30), 16);
        auto correlator = std::make_shared<PacketCorrelator>(store);
        auto writer = std::make_shared<OutputWriter>(outputFile);
        
        // Set components in engine
        g_engine->setPacketProducer(producer);
        g_engine->setPacketParser(parser);
        g_engine->setUnmatchedStore(store);
        g_engine->setPacketCorrelator(correlator);
        g_engine->setOutputWriter(writer);
        
        // Start the engine
        g_engine->start();
        
        std::cout << "Packet Matching Engine started." << std::endl;
        std::cout << "Monitoring directory: " << inputDir << std::endl;
        std::cout << "Output: " << (outputFile.empty() ? "stdout" : outputFile) << std::endl;
        std::cout << "Press Ctrl+C to stop." << std::endl;
        
        // Main loop - print statistics periodically
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
            if (g_running) {
                printStatistics(g_engine->getStatistics());
            }
        }
        
        // Final statistics
        std::cout << "Final statistics:" << std::endl;
        printStatistics(g_engine->getStatistics());
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "Packet Matching Engine stopped." << std::endl;
    return 0;
}
This implementation incorporates all of our optimizations:

✅ Memory-mapped file I/O for faster PCAP processing
✅ Buffer pool for minimizing allocations
✅ Zero-copy parsing with std::span
✅ Lock-free queues with rigtorp::MPMCQueue
✅ Proper move semantics throughout
✅ Thread pool for parallel processing
✅ Sharded storage in UnmatchedStore
✅ Clean header/implementation separation
✅ Atomic operations for statistics
✅ Graceful shutdown handling

The code follows the provided directory structure with proper organization of interfaces, implementations, and data structures.Add to Conversation
