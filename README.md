# gamequant
Project gamequant @ Assonant.ai

Collection and analysis of 2TB+ league of legends match data to recommend game theory optimal ban&pick decisions.


#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctime>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <optional>
#include <memory>
#include <iomanip>

// Configuration structure
struct MarketDataConfig {
    uint16_t udp_port{12345};  // Default market data UDP port
    uint16_t tcp_port{8888};   // Default market data TCP port
    std::vector<std::string> target_symbols{"AAPL", "MSFT", "GOOG"};
};

// Packet information structure
struct PacketInfo {
    uint64_t timestamp_ns{0};      // Nanosecond timestamp
    uint32_t seq_num{0};           // Sequence number (if available in protocol)
    std::string symbol;            // Trading symbol
    std::string event_type;        // Type of market event
    std::vector<uint8_t> raw_data; // Raw packet data for further analysis
    bool is_trigger_event{false};  // Indicates if this event likely triggered a trade
};

// Market data protocol parser
class MarketDataParser {
private:
    MarketDataConfig config_;
    
    // Evaluate if a packet is likely a trade trigger
    bool isLikelyTriggerEvent(const std::string& event_type, 
                             const std::vector<uint8_t>& data) const {
        // This is highly protocol-specific - customize for your market data format
        if (event_type == "TRADE" || event_type == "PRICE_CHANGE" || 
            event_type == "BEST_BID_OFFER_UPDATE") {
            return true;
        }
        
        // Add additional pattern matching logic for your protocol
        return false;
    }
    
    // Parse protocol-specific message
    std::optional<PacketInfo> parseProtocolMessage(
            const uint8_t* payload, 
            size_t payload_len) const {
        // Ensure minimum payload length for parsing
        if (payload_len < 20) {
            return std::nullopt;
        }
        
        PacketInfo info;
        
        // CUSTOMIZATION POINT: Replace this with your actual protocol parsing logic
        // --------------------------------------------------------------------
        // This is an example parsing implementation that should be replaced
        // with parsing code specific to your market data protocol format
        
        // Example: Extract sequence number (first 4 bytes)
        info.seq_num = ntohl(*reinterpret_cast<const uint32_t*>(payload));
        
        // Example: Extract symbol (positions 4-11 contain the symbol)
        char symbol_buf[8] = {0};
        memcpy(symbol_buf, payload + 4, 7);
        info.symbol = symbol_buf;
        
        // Example: Extract message type (position 12)
        char msg_type = static_cast<char>(*(payload + 12));
        switch(msg_type) {
            case 'T': info.event_type = "TRADE"; break;
            case 'Q': info.event_type = "QUOTE"; break;
            case 'O': info.event_type = "ORDER_BOOK"; break;
            default:  info.event_type = "UNKNOWN"; break;
        }
        // --------------------------------------------------------------------
        
        // Save raw data for further analysis if needed
        info.raw_data.assign(payload, payload + payload_len);
        
        // Determine if this is likely a trigger event
        info.is_trigger_event = isLikelyTriggerEvent(info.event_type, info.raw_data);
        
        return info;
    }

public:
    explicit MarketDataParser(MarketDataConfig config = {}) 
        : config_(std::move(config)) {}
    
    void setTargetSymbols(const std::vector<std::string>& symbols) {
        config_.target_symbols = symbols;
    }
    
    // Parse a single packet
    std::optional<PacketInfo> parsePacket(
            const uint8_t* packet, 
            size_t packet_len,
            const struct pcap_pkthdr* header) const {
            
        // Minimal sanity check for packet length
        if (packet_len < 34) { // Ethernet (14) + minimal IP (20)
            return std::nullopt;
        }
        
        // Extract Ethernet header (typically 14 bytes)
        const uint8_t* ip_header = packet + 14;
        
        // Extract IP header
        const struct ip* iph = reinterpret_cast<const struct ip*>(ip_header);
        size_t ip_header_len = iph->ip_hl * 4;
        
        // Check if packet_len is sufficient
        if (packet_len < 14 + ip_header_len + 8) {  // 8 is min UDP/TCP header
            return std::nullopt;
        }
        
        // Protocol-specific processing based on UDP or TCP
        const uint8_t* transport_header = ip_header + ip_header_len;
        const uint8_t* payload = nullptr;
        size_t payload_len = 0;
        bool is_market_data = false;
        
        // Check protocol type
        if (iph->ip_p == IPPROTO_UDP) {
            // UDP packet
            const struct udphdr* udph = reinterpret_cast<const struct udphdr*>(transport_header);
            uint16_t dest_port = ntohs(udph->uh_dport);
            
            is_market_data = (dest_port == config_.udp_port);
            payload = transport_header + 8; // UDP header is 8 bytes
            payload_len = packet_len - (payload - packet);
        }
        else if (iph->ip_p == IPPROTO_TCP) {
            // TCP packet
            const struct tcphdr* tcph = reinterpret_cast<const struct tcphdr*>(transport_header);
            uint16_t dest_port = ntohs(tcph->th_dport);
            
            is_market_data = (dest_port == config_.tcp_port);
            size_t tcp_header_len = tcph->th_off * 4;
            payload = transport_header + tcp_header_len;
            payload_len = packet_len - (payload - packet);
        }
        
        // Skip non-market data packets or empty payloads
        if (!is_market_data || payload_len <= 0) {
            return std::nullopt;
        }
        
        // Try to parse the market data protocol message
        auto info_opt = parseProtocolMessage(payload, payload_len);
        if (!info_opt) {
            return std::nullopt;
        }
        
        // Extract timestamp from packet header
        struct timespec ts;
        
        #ifdef HAVE_PCAP_NG_FORMAT
        // For pcapng format with potential nanosecond precision
        if (header->ts.tv_usec > 1000000) {
            // Nanosecond precision already
            ts.tv_sec = header->ts.tv_sec;
            ts.tv_nsec = header->ts.tv_usec;
        } else {
            // Microsecond precision, convert to nanoseconds
            ts.tv_sec = header->ts.tv_sec;
            ts.tv_nsec = header->ts.tv_usec * 1000;
        }
        #else
        // Standard pcap format (microsecond precision)
        ts.tv_sec = header->ts.tv_sec;
        ts.tv_nsec = header->ts.tv_usec * 1000; // Convert to nanoseconds
        #endif
        
        // Set timestamp in nanoseconds since epoch
        info_opt->timestamp_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + 
                                static_cast<uint64_t>(ts.tv_nsec);
        
        // Filter by symbols of interest
        if (std::find(config_.target_symbols.begin(), config_.target_symbols.end(), 
                     info_opt->symbol) == config_.target_symbols.end()) {
            return std::nullopt;
        }
        
        return info_opt;
    }
};

// PCAP file analyzer
class PcapAnalyzer {
private:
    MarketDataParser parser_;
    std::vector<PacketInfo> market_data_events_;
    
public:
    explicit PcapAnalyzer(MarketDataConfig config = {}) 
        : parser_(std::move(config)) {}
    
    void setTargetSymbols(const std::vector<std::string>& symbols) {
        parser_.setTargetSymbols(symbols);
    }
    
    // Analyze a PCAP file and extract market data events
    [[nodiscard]] bool analyzePcapFile(const std::string& filename) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_offline(filename.c_str(), errbuf);
        
        if (pcap == nullptr) {
            std::cerr << "Error opening pcap file: " << errbuf << std::endl;
            return false;
        }
        
        // Use RAII to ensure pcap is closed
        struct PcapCloser {
            void operator()(pcap_t* p) { if(p) pcap_close(p); }
        };
        std::unique_ptr<pcap_t, PcapCloser> pcap_guard(pcap);
        
        // Try to set timestamp precision to nanoseconds if supported
        #ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
        pcap_set_tstamp_precision(pcap, PCAP_TSTAMP_PRECISION_NANO);
        #endif
        
        struct pcap_pkthdr header;
        const u_char *packet;
        
        // Process each packet in the PCAP file
        while ((packet = pcap_next(pcap, &header)) != nullptr) {
            auto info_opt = parser_.parsePacket(
                packet, header.caplen, &header);
                
            if (info_opt) {
                market_data_events_.push_back(*info_opt);
            }
        }
        
        return true;
    }
    
    // Find events that likely triggered trades
    std::vector<PacketInfo> findTriggerEvents() const {
        std::vector<PacketInfo> triggers;
        triggers.reserve(market_data_events_.size() / 4);  // Reasonable estimate
        
        std::copy_if(market_data_events_.begin(), market_data_events_.end(),
                   std::back_inserter(triggers),
                   [](const PacketInfo& event) { return event.is_trigger_event; });
        
        return triggers;
    }
    
    // Print analysis results to console
    void printResults() const {
        std::cout << "Total market data events found: " << market_data_events_.size() << std::endl;
        
        // Group by symbol
        std::map<std::string, size_t> events_by_symbol;
        for (const auto& event : market_data_events_) {
            events_by_symbol[event.symbol]++;
        }
        
        std::cout << "\nEvents by symbol:" << std::endl;
        for (const auto& pair : events_by_symbol) {
            std::cout << "  " << pair.first << ": " << pair.second << " events" << std::endl;
        }
        
        // Group by event type
        std::map<std::string, size_t> events_by_type;
        for (const auto& event : market_data_events_) {
            events_by_type[event.event_type]++;
        }
        
        std::cout << "\nEvents by type:" << std::endl;
        for (const auto& pair : events_by_type) {
            std::cout << "  " << pair.first << ": " << pair.second << " events" << std::endl;
        }
        
        // Find potential trigger events
        auto triggers = findTriggerEvents();
        std::cout << "\nPotential trigger events: " << triggers.size() << std::endl;
        
        // Print first 10 trigger events
        size_t count = 0;
        for (const auto& event : triggers) {
            if (count++ >= 10) break;
            
            // Convert timestamp to human-readable format
            time_t seconds = event.timestamp_ns / 1000000000ULL;
            uint64_t nanoseconds = event.timestamp_ns % 1000000000ULL;
            
            char time_buffer[80];
            struct tm timeinfo;
            localtime_r(&seconds, &timeinfo);
            strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
            
            std::cout << "\n[" << time_buffer << "." 
                      << std::setfill('0') << std::setw(9) << nanoseconds << "] "
                      << "Symbol: " << event.symbol 
                      << ", Type: " << event.event_type 
                      << ", Seq: " << event.seq_num << std::endl;
        }
    }
    
    // Export results to JSON file
    [[nodiscard]] bool exportToJson(const std::string& filename) const {
        std::ofstream ofs(filename);
        if (!ofs) {
            std::cerr << "Failed to open output file: " << filename << std::endl;
            return false;
        }
        
        // Write JSON format
        ofs << "{\n";
        ofs << "  \"market_data_events\": [\n";
        
        for (size_t i = 0; i < market_data_events_.size(); i++) {
            const auto& event = market_data_events_[i];
            
            ofs << "    {\n";
            ofs << "      \"timestamp_ns\": " << event.timestamp_ns << ",\n";
            ofs << "      \"symbol\": \"" << event.symbol << "\",\n";
            ofs << "      \"event_type\": \"" << event.event_type << "\",\n";
            ofs << "      \"seq_num\": " << event.seq_num << ",\n";
            ofs << "      \"is_trigger\": " << (event.is_trigger_event ? "true" : "false") << "\n";
            
            if (i < market_data_events_.size() - 1) {
                ofs << "    },\n";
            } else {
                ofs << "    }\n";
            }
        }
        
        ofs << "  ]\n";
        ofs << "}\n";
        
        return true;
    }
    
    // Get all collected market data events
    const std::vector<PacketInfo>& getMarketDataEvents() const {
        return market_data_events_;
    }
};

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            std::cout << "Usage: " << argv[0] << " <pcap_file> [output_json]" << std::endl;
            return 1;
        }
        
        const std::string pcap_file = argv[1];
        const std::string output_json = (argc > 2) ? argv[2] : "market_data_events.json";
        
        // Configure the analyzer
        MarketDataConfig config;
        config.udp_port = 12345;  // Set to your market data port
        config.tcp_port = 8888;   // Set to your market data port
        config.target_symbols = {"AAPL", "MSFT", "GOOG"}; // Set your symbols
        
        // Create and run the analyzer
        PcapAnalyzer analyzer(config);
        
        std::cout << "Analyzing PCAP file: " << pcap_file << std::endl;
        if (!analyzer.analyzePcapFile(pcap_file)) {
            std::cerr << "Failed to analyze PCAP file" << std::endl;
            return 1;
        }
        
        // Display and export results
        analyzer.printResults();
        
        std::cout << "\nExporting results to: " << output_json << std::endl;
        if (!analyzer.exportToJson(output_json)) {
            std::cerr << "Failed to export results to JSON" << std::endl;
            return 1;
        }
        
        std::cout << "Analysis complete." << std::endl;
        return 0;
    } 
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}

Code Explanation
The PCAP analyzer is designed to extract market data events from network packet captures and identify potential trade triggers. Here's how it functions:
Core Components

MarketDataConfig: Stores configuration options like which network ports contain market data and which symbols to track.
PacketInfo: A structure that holds parsed information about each market data event:

Timestamp (nanosecond precision)
Sequence number
Symbol (e.g., AAPL, MSFT)
Event type (e.g., TRADE, QUOTE)
Raw data for further processing
Flag indicating if this event likely triggered a trade


MarketDataParser: Responsible for extracting market data from network packets:

parsePacket() processes raw network packets from the PCAP file
parseProtocolMessage() extracts market data protocol information
isLikelyTriggerEvent() identifies events that may trigger orders


PcapAnalyzer: Orchestrates the overall analysis process:

Opens and reads PCAP files
Collects market data events
Generates statistics and reports
Exports results to JSON



Execution Flow

The program reads a PCAP file using libpcap
For each packet in the file:

It extracts the Ethernet, IP, and TCP/UDP headers
It checks if the packet is destined for a configured market data port
If so, it attempts to parse the protocol-specific payload
If parsing succeeds, it extracts the timestamp and adds the event to a collection


After processing all packets, it:

Generates statistics about the market data
Identifies likely trade trigger events
Outputs the results to console and JSON



Mock PCAP Example
Let's imagine a simple PCAP file with two market data packets and see how they would be processed.
Example Packet 1: AAPL Price Update
[Packet Header]
- Timestamp: 2025-04-22 14:30:00.123456789
- Captured length: 78 bytes
- Original length: 78 bytes

[Ethernet Header] (14 bytes)
- Destination MAC: 01:23:45:67:89:ab
- Source MAC: cd:ef:01:23:45:67
- Type: IPv4 (0x0800)

[IP Header] (20 bytes)
- Version: 4
- Header Length: 5 (20 bytes)
- Protocol: UDP (17)
- Source IP: 203.0.113.5
- Destination IP: 192.168.1.10

[UDP Header] (8 bytes)
- Source Port: 34567
- Destination Port: 12345 (matching our configured market data port)
- Length: 36
- Checksum: 0xabcd

[Market Data Payload] (36 bytes)
- Sequence Number: 1234567 (first 4 bytes)
- Symbol: "AAPL   " (next 7 bytes)
- Message Type: 'Q' (Quote update)
- Other protocol-specific data...
Example Packet 2: MSFT Trade Execution
[Packet Header]
- Timestamp: 2025-04-22 14:30:00.123556789 (100μs later)
- Captured length: 82 bytes
- Original length: 82 bytes

[Ethernet Header] (14 bytes)
- Destination MAC: 01:23:45:67:89:ab
- Source MAC: cd:ef:01:23:45:67
- Type: IPv4 (0x0800)

[IP Header] (20 bytes)
- Version: 4
- Header Length: 5 (20 bytes)
- Protocol: UDP (17)
- Source IP: 203.0.113.5
- Destination IP: 192.168.1.10

[UDP Header] (8 bytes)
- Source Port: 34567
- Destination Port: 12345 (matching our configured market data port)
- Length: 40
- Checksum: 0xefab

[Market Data Payload] (40 bytes)
- Sequence Number: 1234568 (first 4 bytes)
- Symbol: "MSFT   " (next 7 bytes)
- Message Type: 'T' (Trade execution)
- Other protocol-specific data...
Processing Flow Example
Here's what happens when these two packets are processed:
Packet 1 Processing

analyzePcapFile() reads the first packet
parsePacket() extracts the network headers:

Identifies UDP protocol
Checks destination port (12345) matches our configured market data port
Extracts the payload


parseProtocolMessage() processes the market data:
cpp// Extract sequence number (first 4 bytes)
info.seq_num = ntohl(*reinterpret_cast<const uint32_t*>(payload));
// = 1234567

// Extract symbol (positions 4-11 contain the symbol)
char symbol_buf[8] = {0};
memcpy(symbol_buf, payload + 4, 7);
info.symbol = symbol_buf;
// = "AAPL"

// Extract message type (position 12)
char msg_type = static_cast<char>(*(payload + 12));
// = 'Q' (QUOTE)

isLikelyTriggerEvent() evaluates if this is a potential trade trigger:

Checks event type "QUOTE" against known trigger types
For this example, returns false (quotes don't trigger trades in our system)


Timestamp extraction:

Converts PCAP header timestamp to nanoseconds (1650624600123456789)
Adds to our market_data_events_ collection



Packet 2 Processing

Similar header processing occurs
parseProtocolMessage() extracts:

Sequence number: 1234568
Symbol: "MSFT"
Message type: 'T' (TRADE)


isLikelyTriggerEvent() evaluates:

Checks event type "TRADE" against known trigger types
Returns true (trades can trigger new orders in our system)


Timestamp extraction:

Converts PCAP header timestamp to nanoseconds (1650624600123556789)
Adds to our market_data_events_ collection



Results Output
After processing, the program outputs:
Total market data events found: 2

Events by symbol:
  AAPL: 1 events
  MSFT: 1 events

Events by type:
  QUOTE: 1 events
  TRADE: 1 events

Potential trigger events: 1

[2025-04-22 14:30:00.123556789] Symbol: MSFT, Type: TRADE, Seq: 1234568
And generates a JSON file:
json{
  "market_data_events": [
    {
      "timestamp_ns": 1650624600123456789,
      "symbol": "AAPL",
      "event_type": "QUOTE",
      "seq_num": 1234567,
      "is_trigger": false
    },
    {
      "timestamp_ns": 1650624600123556789,
      "symbol": "MSFT",
      "event_type": "TRADE",
      "seq_num": 1234568,
      "is_trigger": true
    }
  ]
}
Customization Points
The most significant customization needed for your specific use case will be in the parseProtocolMessage() method, where you'll need to implement the exact parsing logic for your market data protocol. This includes:

Understanding your protocol's binary format
Extracting meaningful fields (prices, quantities, order IDs)
Determining which events should be flagged as potential trade triggers

This implementation provides a solid foundation to build upon, with a clear separation of concerns and a focus on precise timestamp extraction.
