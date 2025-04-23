# gamequant
Project gamequant @ Assonant.ai

Collection and analysis of 2TB+ league of legends match data to recommend game theory optimal ban&pick decisions.
Yes, lock-free programming techniques would be possible and potentially beneficial for this packet matching engine. Several key areas could leverage lock-free programming:

Packet Queue Management:
The current design uses mutex-protected queues for transferring packets between components. This could be replaced with lock-free queue implementations like:

A lock-free ring buffer or SPSC (Single Producer, Single Consumer) queue between the PCAP reader and the processing threads
MPMC (Multiple Producer, Multiple Consumer) queue like moodycamel::ConcurrentQueue for worker thread task distribution


Hash Table Operations:
The packet correlation logic relies heavily on hash tables. These could be replaced with:

Lock-free hash tables using atomic operations (CAS - Compare And Swap)
Techniques like read-copy-update (RCU) for the packet correlation maps
Split hash tables with sharding to minimize contention


Packet Processing Pipeline:

Pipeline stages could use atomics to communicate readiness without locks
A sequence number scheme could ensure proper ordering where needed


Atomic Counters for Statistics:
We already use atomic counters for statistics, but this approach could be expanded to other parts of the system.

Implementation Considerations:

Memory Management:
Lock-free structures require careful memory management. The ABA problem (where a value changes from A to B and back to A, potentially causing incorrect behavior in lock-free algorithms) must be addressed, possibly with:

Memory barriers and fences
Hazard pointers
Epoch-based reclamation


Careful Ordering:
The packet matching relies on proper temporal relationships. Lock-free algorithms would need to maintain correct causal ordering without locks, potentially using:

Memory ordering constraints
Versioned records
Timestamp-based ordering


Complexity vs Performance:
While lock-free programming can offer significant performance benefits in high-contention scenarios, it adds considerable complexity. For this engine, the most beneficial targets would be:

The high-throughput packet ingestion path
The packet matching logic where concurrency is highest
The packet aging/cleanup logic


Platform Considerations:
Effective lock-free programming depends on hardware memory models. Modern x86/x64 provides strong guarantees, but portable lock-free code needs to consider weaker memory models on other architectures using appropriate memory barriers.

Lock-free programming could significantly improve throughput of this engine, potentially eliminating contention bottlenecks during high packet rates. However, it would require careful design and testing to ensure correctness, particularly for the packet correlation logic where proper ordering and matching is critical.
The best approach would be to first implement the current design, profile it under realistic loads, and then selectively replace critical bottlenecks with lock-free alternatives rather than attempting to make the entire system lock-free from the start.

How the Components Work Together

Initialization Flow:

The main() function creates and configures a PacketMatchingEngine
The engine initializes its components: PcapStreamReader, PacketParser, PacketCorrelator, and WorkerPool
IP ranges are configured to determine inbound vs outbound traffic
The engine starts components and creates worker threads


Data Flow:

PcapStreamReader continuously monitors a directory for new PCAP files
When files appear, they're read packet by packet in stream fashion
Packets are placed in a bounded queue for processing
The main thread pulls packets from the queue and distributes them to worker threads
Worker threads parse packets using PacketParser and extract 5-tuple keys and other metadata
Parsed packets are sent to PacketCorrelator
PacketCorrelator tries to match UDP inbound with TCP outbound packets
When matches are found, they're stored in a results queue
The output thread periodically flushes matches to a CSV file


Cleanup and Management:

A cleanup thread in PacketCorrelator removes aged packets that didn't find matches
The main thread periodically logs performance statistics
Signal handlers ensure graceful shutdown on SIGINT (Ctrl+C) or SIGTERM
On shutdown, all queues are flushed, remaining matches are written, and threads terminate



Performance Features

Efficient Memory Usage:

The sliding window approach limits memory consumption
Packets are processed in a streaming fashion, never loading entire PCAP files
Custom buffer management with configurable sizes


Threading Model:

A dedicated thread monitors filesystem for new PCAP files
A thread pool processes packets in parallel
Reader-writer locks (shared_mutex) provide efficient concurrent access
A dedicated output thread handles result storage


Correlation Speed:

Fast hash-based lookup for potential matches
Efficient matching algorithm using payload signatures
Early filtering of unlikely matches


Reliability Features:

Comprehensive logging with rotation
Statistical monitoring to detect anomalies
Graceful handling of overload conditions
Clear error paths with exception handling



Optimization Notes

Memory Efficiency:

Packet data is copied only when necessary
Smart pointer use is minimized to reduce overhead
Fixed-size buffers preallocated where possible


Computational Efficiency:

Custom hash functions optimize 5-tuple key lookups
Batched processing where appropriate
Cache-friendly data structures


Reliability:

Extensive error checking and logging
Resilience to malformed packets
Memory management discipline



Usage Guide
To use the packet matching engine:

Compile the code:
g++ -std=c++17 -o packet_engine main.cpp -lpcap -lpthread

Configure IP ranges:

Edit the IP ranges in main() to match your network setup
Inbound ranges identify "source" networks
Outbound ranges identify "destination" networks


Run the engine:
./packet_engine /path/to/pcap/directory /path/to/output.csv

Monitor performance:

The engine prints stats every 10 seconds
Detailed logs are written to logs/packet_engine.log



This design focuses on simplicity and clarity while still achieving high performance. I've avoided unnecessary template metaprogramming and complex abstraction patterns, instead opting for straightforward, efficient code. The modular structure makes it easy to extend or modify individual components without affecting the overall system.



Core Components Design
1. PCAP Reader Component
#include <pcap.h>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <thread>
#include <filesystem>
#include <spdlog/spdlog.h>

class PcapStreamReader {
private:
    struct PcapPacket {
        struct pcap_pkthdr header;
        std::vector<u_char> data;
    };

    std::atomic<bool> running_{false};
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<PcapPacket> packet_queue_;
    size_t max_queue_size_;
    std::thread reader_thread_;
    std::filesystem::path watch_dir_;
    std::set<std::string> processed_files_;
    
    void reader_loop() {
        while (running_) {
            // Check directory for new files
            std::vector<std::string> new_files;
            for (const auto& entry : std::filesystem::directory_iterator(watch_dir_)) {
                if (entry.is_regular_file() && 
                    entry.path().extension() == ".pcap" &&
                    processed_files_.find(entry.path().string()) == processed_files_.end()) {
                    new_files.push_back(entry.path().string());
                }
            }
            
            // Sort by creation time
            std::sort(new_files.begin(), new_files.end(), [](const std::string& a, const std::string& b) {
                return std::filesystem::last_write_time(a) < std::filesystem::last_write_time(b);
            });
            
            // Process new files
            for (const auto& file : new_files) {
                process_file(file);
                processed_files_.insert(file);
                // Limit memory usage by keeping track of only recent files
                if (processed_files_.size() > 1000) {
                    processed_files_.erase(processed_files_.begin());
                }
            }
            
            // Sleep briefly before checking for new files
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    void process_file(const std::string& filename) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf);
        if (!handle) {
            spdlog::error("Failed to open PCAP file {}: {}", filename, errbuf);
            return;
        }
        
        spdlog::info("Processing PCAP file: {}", filename);
        
        struct pcap_pkthdr header;
        const u_char* packet;
        
        while (running_ && (packet = pcap_next(handle, &header))) {
            // Create a deep copy of the packet data
            std::vector<u_char> packet_data(packet, packet + header.caplen);
            
            // Wait until queue has space
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this]() {
                return packet_queue_.size() < max_queue_size_ || !running_;
            });
            
            if (!running_) break;
            
            // Add packet to queue
            packet_queue_.push({header, std::move(packet_data)});
            lock.unlock();
            queue_cv_.notify_one();
        }
        
        pcap_close(handle);
        spdlog::info("Finished processing file: {}", filename);
    }
    
public:
    PcapStreamReader(size_t max_queue_size = 10000) 
        : max_queue_size_(max_queue_size) {}
    
    ~PcapStreamReader() {
        stop();
    }
    
    void start(const std::string& directory_path) {
        if (running_) return;
        
        watch_dir_ = directory_path;
        running_ = true;
        reader_thread_ = std::thread(&PcapStreamReader::reader_loop, this);
        spdlog::info("PCAP reader started, watching directory: {}", directory_path);
    }
    
    void stop() {
        if (!running_) return;
        
        running_ = false;
        queue_cv_.notify_all();
        if (reader_thread_.joinable()) {
            reader_thread_.join();
        }
        spdlog::info("PCAP reader stopped");
    }
    
    bool get_next_packet(struct pcap_pkthdr& header, std::vector<u_char>& packet_data) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        queue_cv_.wait_for(lock, std::chrono::milliseconds(100), [this]() {
            return !packet_queue_.empty() || !running_;
        });
        
        if (packet_queue_.empty()) {
            return false;
        }
        
        auto packet = std::move(packet_queue_.front());
        packet_queue_.pop();
        
        header = packet.header;
        packet_data = std::move(packet.data);
        
        lock.unlock();
        queue_cv_.notify_one();  // Notify reader that queue has space
        
        return true;
    }
    
    bool is_running() const {
        return running_;
    }
    
    size_t queue_size() const {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return packet_queue_.size();
    }
};

2. Packet Parser and 5-Tuple Key Extractor
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <array>
#include <cstring>
#include <functional>

enum class PacketDirection {
    Unknown,
    Inbound,
    Outbound
};

struct FiveTupleKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    bool operator==(const FiveTupleKey& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

// Custom hash function for FiveTupleKey
namespace std {
    template<>
    struct hash<FiveTupleKey> {
        size_t operator()(const FiveTupleKey& k) const {
            // Simple but effective hash combining technique
            size_t hash = 17;
            hash = hash * 31 + k.src_ip;
            hash = hash * 31 + k.dst_ip;
            hash = hash * 31 + k.src_port;
            hash = hash * 31 + k.dst_port;
            hash = hash * 31 + k.protocol;
            return hash;
        }
    };
}

struct PacketInfo {
    uint64_t timestamp_ns;  // Packet timestamp in nanoseconds
    FiveTupleKey key;       // 5-tuple key
    PacketDirection direction;
    size_t packet_size;
    std::array<uint8_t, 16> payload_hash;  // Store a hash of the payload for verification
    
    // Optional fields for protocol-specific matching
    std::vector<uint8_t> payload_snippet;  // First N bytes of payload for correlation
};

class PacketParser {
private:
    // Configuration
    std::vector<std::pair<uint32_t, uint32_t>> inbound_ip_ranges_;
    std::vector<std::pair<uint32_t, uint32_t>> outbound_ip_ranges_;

    // Determine packet direction based on IP ranges
    PacketDirection determine_direction(uint32_t src_ip, uint32_t dst_ip) const {
        // Check if source is in inbound ranges and destination is in outbound ranges
        bool src_is_inbound = false;
        bool dst_is_outbound = false;
        
        for (const auto& range : inbound_ip_ranges_) {
            if (src_ip >= range.first && src_ip <= range.second) {
                src_is_inbound = true;
                break;
            }
        }
        
        for (const auto& range : outbound_ip_ranges_) {
            if (dst_ip >= range.first && dst_ip <= range.second) {
                dst_is_outbound = true;
                break;
            }
        }
        
        if (src_is_inbound && dst_is_outbound) {
            return PacketDirection::Inbound;
        }
        
        // Check if source is in outbound ranges and destination is in inbound ranges
        bool src_is_outbound = false;
        bool dst_is_inbound = false;
        
        for (const auto& range : outbound_ip_ranges_) {
            if (src_ip >= range.first && src_ip <= range.second) {
                src_is_outbound = true;
                break;
            }
        }
        
        for (const auto& range : inbound_ip_ranges_) {
            if (dst_ip >= range.first && dst_ip <= range.second) {
                dst_is_inbound = true;
                break;
            }
        }
        
        if (src_is_outbound && dst_is_inbound) {
            return PacketDirection::Outbound;
        }
        
        return PacketDirection::Unknown;
    }
    
    // Calculate a simple hash of the payload
    std::array<uint8_t, 16> calculate_payload_hash(const uint8_t* payload, size_t length) const {
        // Simple MD5-like hash function (for demonstration - use a proper hash in production)
        std::array<uint8_t, 16> hash;
        std::fill(hash.begin(), hash.end(), 0);
        
        // Very basic hash calculation
        for (size_t i = 0; i < length; i++) {
            hash[i % 16] ^= payload[i];
            // Rotate bits
            if (i % 16 == 15) {
                for (int j = 0; j < 16; j++) {
                    hash[j] = (hash[j] << 1) | (hash[(j + 1) % 16] >> 7);
                }
            }
        }
        
        return hash;
    }
    
public:
    PacketParser() {
        // Default constructor - configure with specific network settings later
    }
    
    void configure_direction_rules(
        const std::vector<std::pair<uint32_t, uint32_t>>& inbound_ranges,
        const std::vector<std::pair<uint32_t, uint32_t>>& outbound_ranges) {
        inbound_ip_ranges_ = inbound_ranges;
        outbound_ip_ranges_ = outbound_ranges;
    }
    
    std::optional<PacketInfo> parse_packet(const struct pcap_pkthdr& header, const std::vector<u_char>& packet_data) {
        if (packet_data.size() < sizeof(struct ether_header)) {
            return std::nullopt;  // Packet too small to be valid
        }
        
        // Get ethernet header
        const struct ether_header* eth_header = 
            reinterpret_cast<const struct ether_header*>(packet_data.data());
        
        // Verify it's an IP packet
        if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
            return std::nullopt;  // Not an IP packet
        }
        
        // Get IP header
        const struct ip* ip_header = 
            reinterpret_cast<const struct ip*>(packet_data.data() + sizeof(struct ether_header));
        int ip_header_len = ip_header->ip_hl * 4;
        
        // Extract source and destination IPs
        uint32_t src_ip = ntohl(ip_header->ip_src.s_addr);
        uint32_t dst_ip = ntohl(ip_header->ip_dst.s_addr);
        
        // Initialize packet info structure
        PacketInfo info;
        info.timestamp_ns = 
            static_cast<uint64_t>(header.ts.tv_sec) * 1000000000ULL + header.ts.tv_usec * 1000ULL;
        info.packet_size = header.len;
        info.direction = determine_direction(src_ip, dst_ip);
        
        // Extract protocol-specific information
        if (ip_header->ip_p == IPPROTO_TCP) {
            // TCP packet
            const struct tcphdr* tcp_header = 
                reinterpret_cast<const struct tcphdr*>(
                    packet_data.data() + sizeof(struct ether_header) + ip_header_len);
            
            // Fill in 5-tuple key
            info.key.src_ip = src_ip;
            info.key.dst_ip = dst_ip;
            info.key.src_port = ntohs(tcp_header->th_sport);
            info.key.dst_port = ntohs(tcp_header->th_dport);
            info.key.protocol = IPPROTO_TCP;
            
            // Calculate payload offset and size
            size_t tcp_header_len = tcp_header->th_off * 4;
            size_t payload_offset = sizeof(struct ether_header) + ip_header_len + tcp_header_len;
            
            // Extract payload snippet if any
            if (packet_data.size() > payload_offset) {
                const uint8_t* payload = packet_data.data() + payload_offset;
                size_t payload_size = packet_data.size() - payload_offset;
                
                // Calculate payload hash
                info.payload_hash = calculate_payload_hash(payload, payload_size);
                
                // Store payload snippet (first 64 bytes or less)
                size_t snippet_size = std::min(payload_size, size_t(64));
                info.payload_snippet.assign(payload, payload + snippet_size);
            }
            
            return info;
        } 
        else if (ip_header->ip_p == IPPROTO_UDP) {
            // UDP packet
            const struct udphdr* udp_header = 
                reinterpret_cast<const struct udphdr*>(
                    packet_data.data() + sizeof(struct ether_header) + ip_header_len);
            
            // Fill in 5-tuple key
            info.key.src_ip = src_ip;
            info.key.dst_ip = dst_ip;
            info.key.src_port = ntohs(udp_header->uh_sport);
            info.key.dst_port = ntohs(udp_header->uh_dport);
            info.key.protocol = IPPROTO_UDP;
            
            // Calculate payload offset and size
            size_t payload_offset = sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr);
            
            // Extract payload snippet if any
            if (packet_data.size() > payload_offset) {
                const uint8_t* payload = packet_data.data() + payload_offset;
                size_t payload_size = packet_data.size() - payload_offset;
                
                // Calculate payload hash
                info.payload_hash = calculate_payload_hash(payload, payload_size);
                
                // Store payload snippet (first 64 bytes or less)
                size_t snippet_size = std::min(payload_size, size_t(64));
                info.payload_snippet.assign(payload, payload + snippet_size);
            }
            
            return info;
        }
        
        // Not a TCP or UDP packet
        return std::nullopt;
    }
};

3. Packet Correlator - Matching Engine Core
#include <chrono>
#include <unordered_map>
#include <optional>
#include <vector>
#include <mutex>
#include <shared_mutex>
#include <algorithm>

struct MatchResult {
    PacketInfo inbound_packet;
    PacketInfo outbound_packet;
    uint64_t latency_ns;
};

class PacketCorrelator {
private:
    // Configuration
    std::chrono::milliseconds max_retention_time_;  // Maximum time to keep unmatched packets
    std::chrono::milliseconds max_correlation_latency_;  // Maximum allowed latency between request and response
    
    // Thread-safe storage for unmatched packets
    mutable std::shared_mutex inbound_mutex_;
    std::unordered_map<FiveTupleKey, PacketInfo> unmatched_inbound_;
    
    mutable std::shared_mutex outbound_mutex_;
    std::unordered_map<FiveTupleKey, PacketInfo> unmatched_outbound_;
    
    // Matched packet storage
    mutable std::mutex match_mutex_;
    std::vector<MatchResult> matches_;
    
    // Stats
    std::atomic<size_t> total_inbound_{0};
    std::atomic<size_t> total_outbound_{0};
    std::atomic<size_t> total_matches_{0};
    std::atomic<size_t> expired_packets_{0};
    
    // Cleanup thread for removing expired packets
    std::thread cleanup_thread_;
    std::atomic<bool> running_{false};
    
    // Advanced correlation logic for UDP-TCP pairs
    bool correlate_udp_tcp(const PacketInfo& udp_packet, const PacketInfo& tcp_packet) const {
        // Verify directionality - UDP should be inbound, TCP outbound
        if (udp_packet.direction != PacketDirection::Inbound || 
            tcp_packet.direction != PacketDirection::Outbound) {
            return false;
        }
        
        // Check time constraints - TCP must follow UDP within reasonable time
        if (tcp_packet.timestamp_ns <= udp_packet.timestamp_ns) {
            return false;  // TCP packet can't precede UDP packet
        }
        
        uint64_t latency = tcp_packet.timestamp_ns - udp_packet.timestamp_ns;
        if (latency > max_correlation_latency_.count() * 1000000) {
            return false;  // Latency too high
        }
        
        // Protocol-specific correlation logic
        // This is where you'd implement your specific matching logic based on:
        // 1. Payload inspection
        // 2. Known patterns in request-response
        // 3. Application-specific identifiers in packets
        
        // Simple correlation - check if payload snippets contain common patterns
        // This is highly application-specific and would need customization
        if (!udp_packet.payload_snippet.empty() && !tcp_packet.payload_snippet.empty()) {
            // Look for pattern where TCP payload contains parts of UDP payload
            // Just a simplified example - real matching would be more sophisticated
            for (size_t i = 0; i < udp_packet.payload_snippet.size() - 3; i++) {
                // Look for at least 4 consecutive bytes that match
                if (std::search(tcp_packet.payload_snippet.begin(), tcp_packet.payload_snippet.end(),
                               udp_packet.payload_snippet.begin() + i, 
                               udp_packet.payload_snippet.begin() + i + 4) != tcp_packet.payload_snippet.end()) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    void cleanup_loop() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            auto now = std::chrono::steady_clock::now();
            auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                now.time_since_epoch()).count();
            
            size_t expired_count = 0;
            
            // Clean up inbound packets
            {
                std::unique_lock<std::shared_mutex> lock(inbound_mutex_);
                for (auto it = unmatched_inbound_.begin(); it != unmatched_inbound_.end();) {
                    if (now_ns - it->second.timestamp_ns > max_retention_time_.count() * 1000000) {
                        it = unmatched_inbound_.erase(it);
                        expired_count++;
                    } else {
                        ++it;
                    }
                }
            }
            
            // Clean up outbound packets
            {
                std::unique_lock<std::shared_mutex> lock(outbound_mutex_);
                for (auto it = unmatched_outbound_.begin(); it != unmatched_outbound_.end();) {
                    if (now_ns - it->second.timestamp_ns > max_retention_time_.count() * 1000000) {
                        it = unmatched_outbound_.erase(it);
                        expired_count++;
                    } else {
                        ++it;
                    }
                }
            }
            
            expired_packets_ += expired_count;
        }
    }
    
public:
    PacketCorrelator(std::chrono::milliseconds retention_time = std::chrono::seconds(30),
                    std::chrono::milliseconds max_latency = std::chrono::seconds(5))
        : max_retention_time_(retention_time), max_correlation_latency_(max_latency) {}
    
    ~PacketCorrelator() {
        stop();
    }
    
    void start() {
        if (running_) return;
        
        running_ = true;
        cleanup_thread_ = std::thread(&PacketCorrelator::cleanup_loop, this);
        spdlog::info("Packet correlator started");
    }
    
    void stop() {
        if (!running_) return;
        
        running_ = false;
        if (cleanup_thread_.joinable()) {
            cleanup_thread_.join();
        }
        spdlog::info("Packet correlator stopped");
    }
    
    void process_packet(const PacketInfo& packet) {
        // Check packet direction and process accordingly
        if (packet.direction == PacketDirection::Inbound && packet.key.protocol == IPPROTO_UDP) {
            total_inbound_++;
            
            // Store inbound UDP packet
            {
                std::unique_lock<std::shared_mutex> lock(inbound_mutex_);
                unmatched_inbound_[packet.key] = packet;
            }
            
            // Try to find matching TCP outbound packet
            std::vector<FiveTupleKey> potential_matches;
            {
                std::shared_lock<std::shared_mutex> lock(outbound_mutex_);
                for (const auto& [key, outbound_packet] : unmatched_outbound_) {
                    if (outbound_packet.key.protocol == IPPROTO_TCP &&
                        correlate_udp_tcp(packet, outbound_packet)) {
                        potential_matches.push_back(key);
                    }
                }
            }
            
            // Process potential matches
            for (const auto& key : potential_matches) {
                PacketInfo outbound_packet;
                {
                    std::unique_lock<std::shared_mutex> lock(outbound_mutex_);
                    auto it = unmatched_outbound_.find(key);
                    if (it != unmatched_outbound_.end()) {
                        outbound_packet = it->second;
                        unmatched_outbound_.erase(it);
                    } else {
                        continue;  // Packet was already matched by another thread
                    }
                }
                
                // Create match
                MatchResult match;
                match.inbound_packet = packet;
                match.outbound_packet = outbound_packet;
                match.latency_ns = outbound_packet.timestamp_ns - packet.timestamp_ns;
                
                // Store match
                {
                    std::lock_guard<std::mutex> lock(match_mutex_);
                    matches_.push_back(match);
                }
                
                total_matches_++;
                
                // Remove packet from inbound map since it's matched
                {
                    std::unique_lock<std::shared_mutex> lock(inbound_mutex_);
                    unmatched_inbound_.erase(packet.key);
                }
                
                break;  // Only use the first match found
            }
        }
        else if (packet.direction == PacketDirection::Outbound && packet.key.protocol == IPPROTO_TCP) {
            total_outbound_++;
            
            // Try to find matching UDP inbound packet
            std::vector<FiveTupleKey> potential_matches;
            {
                std::shared_lock<std::shared_mutex> lock(inbound_mutex_);
                for (const auto& [key, inbound_packet] : unmatched_inbound_) {
                    if (inbound_packet.key.protocol == IPPROTO_UDP &&
                        correlate_udp_tcp(inbound_packet, packet)) {
                        potential_matches.push_back(key);
                    }
                }
            }
            
            // Process potential matches
            for (const auto& key : potential_matches) {
                PacketInfo inbound_packet;
                {
                    std::unique_lock<std::shared_mutex> lock(inbound_mutex_);
                    auto it = unmatched_inbound_.find(key);
                    if (it != unmatched_inbound_.end()) {
                        inbound_packet = it->second;
                        unmatched_inbound_.erase(it);
                    } else {
                        continue;  // Packet was already matched by another thread
                    }
                }
                
                // Create match
                MatchResult match;
                match.inbound_packet = inbound_packet;
                match.outbound_packet = packet;
                match.latency_ns = packet.timestamp_ns - inbound_packet.timestamp_ns;
                
                // Store match
                {
                    std::lock_guard<std::mutex> lock(match_mutex_);
                    matches_.push_back(match);
                }
                
                total_matches_++;
                
                // Don't store this outbound packet since it's matched
                return;
            }
            
            // If no match found, store outbound packet
            {
                std::unique_lock<std::shared_mutex> lock(outbound_mutex_);
                unmatched_outbound_[packet.key] = packet;
            }
        }
    }
    
    std::vector<MatchResult> get_matches(size_t max_count = 1000) {
        std::lock_guard<std::mutex> lock(match_mutex_);
        
        std::vector<MatchResult> result;
        if (matches_.empty()) {
            return result;
        }
        
        size_t count = std::min(max_count, matches_.size());
        result.reserve(count);
        
        // Return oldest matches first
        std::copy(matches_.begin(), matches_.begin() + count, std::back_inserter(result));
        
        // Remove returned matches
        matches_.erase(matches_.begin(), matches_.begin() + count);
        
        return result;
    }
    
    // Get statistics
    struct Stats {
        size_t inbound_packets;
        size_t outbound_packets;
        size_t matched_pairs;
        size_t unmatched_inbound;
        size_t unmatched_outbound;
        size_t expired_packets;
    };
    
    Stats get_stats() const {
        Stats stats;
        stats.inbound_packets = total_inbound_;
        stats.outbound_packets = total_outbound_;
        stats.matched_pairs = total_matches_;
        stats.expired_packets = expired_packets_;
        
        {
            std::shared_lock<std::shared_mutex> lock(inbound_mutex_);
            stats.unmatched_inbound = unmatched_inbound_.size();
        }
        
        {
            std::shared_lock<std::shared_mutex> lock(outbound_mutex_);
            stats.unmatched_outbound = unmatched_outbound_.size();
        }
        
        return stats;
    }
};

4. Worker Pool for Parallel Processing
#include <thread>
#include <vector>
#include <queue>
#include <functional>
#include <condition_variable>
#include <atomic>

class WorkerPool {
private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    std::atomic<bool> stop_{false};
    
    void worker_loop() {
        while (true) {
            std::function<void()> task;
            
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                condition_.wait(lock, [this]() {
                    return stop_ || !tasks_.empty();
                });
                
                if (stop_ && tasks_.empty()) {
                    return;
                }
                
                task = std::move(tasks_.front());
                tasks_.pop();
            }
            
            task();
        }
    }
    
public:
    WorkerPool(size_t num_threads) {
        workers_.reserve(num_threads);
        for (size_t i = 0; i < num_threads; ++i) {
            workers_.emplace_back(&WorkerPool::worker_loop, this);
        }
    }
    
    ~WorkerPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            stop_ = true;
        }
        
        condition_.notify_all();
        
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }
    
    template<class F>
    void enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            tasks_.emplace(std::forward<F>(f));
        }
        
        condition_.notify_one();
    }
    
    size_t get_thread_count() const {
        return workers_.size();
    }
    
    size_t get_pending_tasks() const {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        return tasks_.size();
    }
};
5. Main Engine Class
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <chrono>
#include <thread>
#include <atomic>
#include <fstream>
class PacketMatchingEngine {
private:
    // Components
    PcapStreamReader pcap_reader_;
    PacketParser packet_parser_;
    PacketCorrelator packet_correlator_;
    WorkerPool worker_pool_;
    
    // Engine state
    std::atomic<bool> running_{false};
    std::thread main_thread_;
    std::thread output_thread_;
    std::string output_file_path_;
    
    // Stats
    std::atomic<size_t> processed_packets_{0};
    std::atomic<size_t> failed_parse_{0};
    std::chrono::time_point<std::chrono::steady_clock> start_time_;
    
    void main_loop() {
        spdlog::info("Main processing loop started");
        
        while (running_) {
            // Get next packet from the reader
            struct pcap_pkthdr header;
            std::vector<u_char> packet_data;
            
            if (pcap_reader_.get_next_packet(header, packet_data)) {
                // Increment counter
                processed_packets_++;
                
                // Submit packet for processing
                worker_pool_.enqueue([this, header, packet_data = std::move(packet_data)]() {
                    // Parse packet
                    auto packet_info = packet_parser_.parse_packet(header, packet_data);
                    
                    if (!packet_info) {
                        failed_parse_++;
                        return;
                    }
                    
                    // Send to correlator
                    packet_correlator_.process_packet(*packet_info);
                });
            } else {
                // No packets available, sleep briefly
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            
            // Periodically log stats (every 10000 packets)
            if (processed_packets_ % 10000 == 0) {
                log_stats();
            }
        }
        
        spdlog::info("Main processing loop stopped");
    }
    
    void output_loop() {
        spdlog::info("Output loop started");
        
        std::ofstream output_file(output_file_path_, std::ios::app);
        if (!output_file) {
            spdlog::error("Failed to open output file: {}", output_file_path_);
            return;
        }
        
        // Write header if file is empty
        if (output_file.tellp() == 0) {
            output_file << "inbound_timestamp,outbound_timestamp,latency_ns,"
                        << "src_ip,dst_ip,src_port,dst_port,protocol\n";
        }
        
        while (running_) {
            // Get matches from correlator
            auto matches = packet_correlator_.get_matches(1000);
            
            // Write matches to file
            for (const auto& match : matches) {
                output_file << match.inbound_packet.timestamp_ns << ","
                           << match.outbound_packet.timestamp_ns << ","
                           << match.latency_ns << ","
                           << match.inbound_packet.key.src_ip << ","
                           << match.inbound_packet.key.dst_ip << ","
                           << match.inbound_packet.key.src_port << ","
                           << match.inbound_packet.key.dst_port << ","
                           << static_cast<int>(match.inbound_packet.key.protocol) << "\n";
            }
            
            output_file.flush();
            
            // Sleep if no matches were found
            if (matches.empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        
        // Process any remaining matches
        auto final_matches = packet_correlator_.get_matches();
        for (const auto& match : final_matches) {
            output_file << match.inbound_packet.timestamp_ns << ","
                       << match.outbound_packet.timestamp_ns << ","
                       << match.latency_ns << ","
                       << match.inbound_packet.key.src_ip << ","
                       << match.inbound_packet.key.dst_ip << ","
                       << match.inbound_packet.key.src_port << ","
                       << match.inbound_packet.key.dst_port << ","
                       << static_cast<int>(match.inbound_packet.key.protocol) << "\n";
        }
        
        output_file.close();
        spdlog::info("Output loop stopped");
    }
    
    void log_stats() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count();
        
        if (elapsed == 0) elapsed = 1;  // Avoid division by zero
        
        auto correlator_stats = packet_correlator_.get_stats();
        
        spdlog::info("--- Performance Statistics ---");
        spdlog::info("Running time: {}s", elapsed);
        spdlog::info("Processed packets: {} ({}/s)", 
                     processed_packets_.load(), processed_packets_.load() / elapsed);
        spdlog::info("Failed to parse: {} ({:.2f}%)", 
                     failed_parse_.load(), 
                     100.0 * failed_parse_.load() / std::max<size_t>(1, processed_packets_.load()));
        spdlog::info("Inbound packets: {}", correlator_stats.inbound_packets);
        spdlog::info("Outbound packets: {}", correlator_stats.outbound_packets);
        spdlog::info("Matched pairs: {}", correlator_stats.matched_pairs);
        spdlog::info("Unmatched inbound: {}", correlator_stats.unmatched_inbound);
        spdlog::info("Unmatched outbound: {}", correlator_stats.unmatched_outbound);
        spdlog::info("Expired packets: {}", correlator_stats.expired_packets);
        spdlog::info("Worker queue size: {}", worker_pool_.get_pending_tasks());
        spdlog::info("Reader queue size: {}", pcap_reader_.queue_size());
    }
    
public:
    PacketMatchingEngine(
        size_t max_queue_size = 10000,
        size_t num_worker_threads = 4,
        std::chrono::milliseconds retention_time = std::chrono::seconds(30),
        std::chrono::milliseconds max_latency = std::chrono::seconds(5),
        const std::string& output_path = "packet_matches.csv")
        : pcap_reader_(max_queue_size),
          packet_correlator_(retention_time, max_latency),
          worker_pool_(num_worker_threads),
          output_file_path_(output_path) {
        
        // Initialize logging
        try {
            auto rotating_logger = spdlog::rotating_logger_mt(
                "packet_engine", "logs/packet_engine.log", 
                10 * 1024 * 1024,  // 10 MB max file size
                5);                // Keep 5 files
            spdlog::set_default_logger(rotating_logger);
            spdlog::flush_on(spdlog::level::info);
        } catch (const spdlog::spdlog_ex& ex) {
            std::cerr << "Log initialization failed: " << ex.what() << std::endl;
        }
    }
    
    ~PacketMatchingEngine() {
        stop();
    }
    
    void configure_parser(
        const std::vector<std::pair<uint32_t, uint32_t>>& inbound_ranges,
        const std::vector<std::pair<uint32_t, uint32_t>>& outbound_ranges) {
        packet_parser_.configure_direction_rules(inbound_ranges, outbound_ranges);
    }
    
    void start(const std::string& pcap_directory) {
        if (running_) return;
        
        spdlog::info("Starting packet matching engine");
        running_ = true;
        start_time_ = std::chrono::steady_clock::now();
        
        // Start components
        packet_correlator_.start();
        pcap_reader_.start(pcap_directory);
        
        // Start processing threads
        main_thread_ = std::thread(&PacketMatchingEngine::main_loop, this);
        output_thread_ = std::thread(&PacketMatchingEngine::output_loop, this);
        
        spdlog::info("Packet matching engine started");
    }
    
    void stop() {
        if (!running_) return;
        
        spdlog::info("Stopping packet matching engine");
        running_ = false;
        
        // Wait for threads to finish
        if (main_thread_.joinable()) {
            main_thread_.join();
        }
        
        if (output_thread_.joinable()) {
            output_thread_.join();
        }
        
        // Stop components
        pcap_reader_.stop();
        packet_correlator_.stop();
        
        // Log final stats
        log_stats();
        
        spdlog::info("Packet matching engine stopped");
    }
    
    // Get current statistics
    struct EngineStats {
        size_t processed_packets;
        size_t failed_parse;
        size_t inbound_packets;
        size_t outbound_packets;
        size_t matched_pairs;
        size_t unmatched_inbound;
        size_t unmatched_outbound;
        size_t expired_packets;
        size_t worker_queue_size;
        size_t reader_queue_size;
        double runtime_seconds;
        double packets_per_second;
    };
    
    EngineStats get_stats() const {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count();
        
        auto correlator_stats = packet_correlator_.get_stats();
        
        EngineStats stats;
        stats.processed_packets = processed_packets_;
        stats.failed_parse = failed_parse_;
        stats.inbound_packets = correlator_stats.inbound_packets;
        stats.outbound_packets = correlator_stats.outbound_packets;
        stats.matched_pairs = correlator_stats.matched_pairs;
        stats.unmatched_inbound = correlator_stats.unmatched_inbound;
        stats.unmatched_outbound = correlator_stats.unmatched_outbound;
        stats.expired_packets = correlator_stats.expired_packets;
        stats.worker_queue_size = worker_pool_.get_pending_tasks();
        stats.reader_queue_size = pcap_reader_.queue_size();
        stats.runtime_seconds = elapsed;
        stats.packets_per_second = elapsed > 0 ? static_cast<double>(processed_packets_) / elapsed : 0;
        
        return stats;
    }
};

6. Main Program and Configuration
#include <iostream>
#include <string>
#include <vector>
#include <csignal>
#include <unistd.h>

// Global reference for signal handling
PacketMatchingEngine* g_engine = nullptr;

void signal_handler(int signal) {
    if (g_engine) {
        std::cout << "Received signal " << signal << ", shutting down..." << std::endl;
        g_engine->stop();
    }
}

// Helper function to convert IP string to uint32_t
uint32_t ip_to_uint32(const std::string& ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        throw std::runtime_error("Invalid IP address: " + ip_str);
    }
    return ntohl(addr.s_addr);
}

int main(int argc, char* argv[]) {
    try {
        // Parse command line arguments
        if (argc < 2) {
            std::cerr << "Usage: " << argv[0] << " <pcap_directory> [output_file]" << std::endl;
            return 1;
        }
        
        std::string pcap_directory = argv[1];
        std::string output_file = argc > 2 ? argv[2] : "packet_matches.csv";
        
        // Configure the engine
        size_t num_threads = std::thread::hardware_concurrency();
        size_t queue_size = 100000;  // Adjust based on expected traffic volume
        std::chrono::milliseconds retention_time(30000);  // 30 seconds
        std::chrono::milliseconds max_latency(5000);      // 5 seconds
        
        // Create engine
        PacketMatchingEngine engine(queue_size, num_threads, retention_time, max_latency, output_file);
        g_engine = &engine;
        
        // Set up signal handlers
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        
        // Configure network direction rules
        // Example: 192.168.1.0/24 as inbound, 10.0.0.0/8 as outbound
        std::vector<std::pair<uint32_t, uint32_t>> inbound_ranges = {
            {ip_to_uint32("192.168.1.0"), ip_to_uint32("192.168.1.255")}
        };
        
        std::vector<std::pair<uint32_t, uint32_t>> outbound_ranges = {
            {ip_to_uint32("10.0.0.0"), ip_to_uint32("10.255.255.255")}
        };
        
        engine.configure_parser(inbound_ranges, outbound_ranges);
        
        // Start the engine
        std::cout << "Starting packet matching engine..." << std::endl;
        std::cout << "Monitoring directory: " << pcap_directory << std::endl;
        std::cout << "Writing results to: " << output_file << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl;
        
        engine.start(pcap_directory);
        
        // Main thread just waits for signals
        while (true) {
            sleep(10);
            
            // Print stats periodically
            auto stats = engine.get_stats();
            std::cout << "Processed: " << stats.processed_packets 
                     << " packets (" << stats.packets_per_second << "/s), "
                     << "Matches: " << stats.matched_pairs << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
