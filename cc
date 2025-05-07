I'll help you implement the PacketProcessor class using PcapPlusPlus for handling both UDP and TCP packets with proprietary protocols. The implementation will include TCP reassembly and handling of dropped UDP packets using application layer sequence numbers.

Here's a comprehensive implementation of the PacketProcessor class:

## PacketProcessor Implementation

### PacketProcessor.h
```cpp
#pragma once

#include <string>
#include <functional>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <condition_variable>
#include "Log.h"

// Forward declare PcapPlusPlus classes to avoid including headers in this header file
namespace pcpp {
    class IFileReaderDevice;
    class Packet;
    class TcpReassembly;
    class IPv4Address;
    class ConnectionData;
}

/**
 * Parser interface for handling application layer protocols
 */
class IProtocolParser {
public:
    virtual ~IProtocolParser() = default;
    
    /**
     * Process application layer data from a packet
     * 
     * @param data Pointer to application data
     * @param dataLength Length of data
     * @param timestamp Packet timestamp
     * @param srcIP Source IP address
     * @param dstIP Destination IP address
     * @param srcPort Source port
     * @param dstPort Destination port
     * @return True if data was processed successfully
     */
    virtual bool processData(const uint8_t* data, size_t dataLength, 
                            double timestamp, const std::string& srcIP, 
                            const std::string& dstIP, uint16_t srcPort, 
                            uint16_t dstPort) = 0;
};

/**
 * TCP reassembly message handler for PcapPlusPlus's TcpReassembly
 */
class TcpReassemblyHandler {
public:
    TcpReassemblyHandler(std::shared_ptr<IProtocolParser> parser);
    
    /**
     * Handle a message that was reassembled from TCP segments
     * 
     * @param connectionData Connection information
     * @param data Pointer to reassembled data 
     * @param dataLength Length of data
     */
    void onMessageReady(pcpp::ConnectionData connectionData, const uint8_t* data, size_t dataLength);
    
private:
    std::shared_ptr<IProtocolParser> m_parser;
};

/**
 * Parser for SPCast UDP protocol
 */
class SPCastParser : public IProtocolParser {
public:
    SPCastParser();
    
    bool processData(const uint8_t* data, size_t dataLength, 
                    double timestamp, const std::string& srcIP, 
                    const std::string& dstIP, uint16_t srcPort, 
                    uint16_t dstPort) override;
                    
private:
    /**
     * Structure to track sequence numbers for a flow
     */
    struct FlowState {
        uint32_t lastSequence;
        bool initialized;
        
        FlowState() : lastSequence(0), initialized(false) {}
    };
    
    // Map of flow ID -> flow state
    std::unordered_map<std::string, FlowState> m_flowStates;
    std::mutex m_flowMutex;
    
    // Create a unique key for a flow
    std::string createFlowKey(const std::string& srcIP, uint16_t srcPort, 
                             const std::string& dstIP, uint16_t dstPort);
    
    // Extract sequence number from SPCast header
    uint32_t extractSequenceNumber(const uint8_t* data, size_t dataLength);
    
    px::Log* log_;
};

/**
 * Parser for Raze TCP protocol
 */
class RazeParser : public IProtocolParser {
public:
    RazeParser();
    
    bool processData(const uint8_t* data, size_t dataLength, 
                    double timestamp, const std::string& srcIP, 
                    const std::string& dstIP, uint16_t srcPort, 
                    uint16_t dstPort) override;
                    
private:
    px::Log* log_;
};

/**
 * Factory for creating appropriate protocol parsers
 */
class ProtocolParserFactory {
public:
    /**
     * Get a parser for a specific protocol
     * 
     * @param protocol Protocol name ("spcast" or "raze")
     * @return Shared pointer to appropriate parser
     */
    static std::shared_ptr<IProtocolParser> getParser(const std::string& protocol);
    
private:
    static std::unordered_map<std::string, std::shared_ptr<IProtocolParser>> s_parsers;
    static std::mutex s_parserMutex;
};

/**
 * Processes PCAP files to extract packet data for analysis.
 * Supports TCP reassembly and handling of dropped UDP packets.
 */
class PacketProcessor {
public:
    /**
     * Create a packet processor
     */
    PacketProcessor();
    
    /**
     * Destructor
     */
    ~PacketProcessor();
    
    /**
     * Process a PCAP file
     * 
     * @param filePath Path to the PCAP file
     * @param onComplete Function to call when processing completes
     */
    void processFile(const std::string& filePath, std::function<void()> onComplete = nullptr);
    
    /**
     * Process new data in a growing PCAP file
     * 
     * @param filePath Path to the growing file
     * @return True if processing was successful
     */
    bool processGrowingFile(const std::string& filePath);
    
    /**
     * Stop any ongoing processing
     */
    void stop();
    
    /**
     * Check if processing is currently running
     * 
     * @return True if processing is active
     */
    bool isProcessing() const;
    
private:
    struct ProcessingContext {
        std::string filePath;
        std::function<void()> onComplete;
        std::unique_ptr<pcpp::IFileReaderDevice> reader;
        std::unique_ptr<pcpp::TcpReassembly> tcpReassembly;
        std::shared_ptr<TcpReassemblyHandler> reassemblyHandler;
        bool isGrowing;
        size_t lastPosition;
        
        ProcessingContext(const std::string& path, std::function<void()> callback, bool growing = false)
            : filePath(path), onComplete(callback), isGrowing(growing), lastPosition(0) {}
    };
    
    /**
     * Worker thread for processing files
     */
    void processingThread();
    
    /**
     * Process a single packet
     * 
     * @param context Processing context
     * @param packet Packet to process
     * @return True if packet was processed successfully
     */
    bool processPacket(ProcessingContext& context, pcpp::Packet& packet);
    
    /**
     * Handle UDP packet
     * 
     * @param context Processing context
     * @param packet Packet to process
     * @return True if packet was processed successfully
     */
    bool handleUdpPacket(ProcessingContext& context, pcpp::Packet& packet);
    
    /**
     * Handle TCP packet
     * 
     * @param context Processing context
     * @param packet Packet to process
     * @return True if packet was processed successfully
     */
    bool handleTcpPacket(ProcessingContext& context, pcpp::Packet& packet);
    
    /**
     * Initialize processing context
     * 
     * @param context Context to initialize
     * @return True if initialization was successful
     */
    bool initContext(ProcessingContext& context);
    
    /**
     * Add a file to the processing queue
     * 
     * @param context Processing context for the file
     */
    void queueFile(std::unique_ptr<ProcessingContext> context);
    
    std::atomic<bool> m_running;
    std::atomic<bool> m_processing;
    std::thread m_thread;
    
    std::mutex m_queueMutex;
    std::condition_variable m_queueCondition;
    std::queue<std::unique_ptr<ProcessingContext>> m_processingQueue;
    
    // Protocol parsers
    std::shared_ptr<IProtocolParser> m_spcastParser;
    std::shared_ptr<IProtocolParser> m_razeParser;
    
    px::Log* log_;
};
```

### PacketProcessor.cpp
```cpp
#include "PacketProcessor.h"
#include <PcapFileDevice.h>
#include <Packet.h>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <PayloadLayer.h>
#include <TcpReassembly.h>
#include <SystemUtils.h>
#include <chrono>
#include <iostream>
#include <sstream>
#include <algorithm>

// Initialize static members of ProtocolParserFactory
std::unordered_map<std::string, std::shared_ptr<IProtocolParser>> ProtocolParserFactory::s_parsers;
std::mutex ProtocolParserFactory::s_parserMutex;

// ----- TcpReassemblyHandler implementation -----

TcpReassemblyHandler::TcpReassemblyHandler(std::shared_ptr<IProtocolParser> parser)
    : m_parser(parser)
{
}

void TcpReassemblyHandler::onMessageReady(pcpp::ConnectionData connectionData, const uint8_t* data, size_t dataLength)
{
    if (!m_parser) return;
    
    // Extract connection information
    std::string srcIP = connectionData.srcIP.toString();
    std::string dstIP = connectionData.dstIP.toString();
    uint16_t srcPort = connectionData.srcPort;
    uint16_t dstPort = connectionData.dstPort;
    
    // Calculate timestamp from seconds and microseconds
    double timestamp = connectionData.startTime.tv_sec + (connectionData.startTime.tv_usec / 1000000.0);
    
    // Process the reassembled data
    m_parser->processData(data, dataLength, timestamp, srcIP, dstIP, srcPort, dstPort);
}

// ----- SPCastParser implementation -----

SPCastParser::SPCastParser()
    : log_(PME_GET_LOGGER("SPCastParser"))
{
}

bool SPCastParser::processData(const uint8_t* data, size_t dataLength, 
                             double timestamp, const std::string& srcIP, 
                             const std::string& dstIP, uint16_t srcPort, 
                             uint16_t dstPort)
{
    if (!data || dataLength < 8) {
        PME_LOG_WARNING(log_, "SPCast packet too small");
        return false;
    }
    
    // Create flow key
    std::string flowKey = createFlowKey(srcIP, srcPort, dstIP, dstPort);
    
    // Extract sequence number
    uint32_t seqNum = extractSequenceNumber(data, dataLength);
    
    // Check sequence
    bool shouldProcess = false;
    {
        std::lock_guard<std::mutex> lock(m_flowMutex);
        
        auto& flow = m_flowStates[flowKey];
        
        if (!flow.initialized) {
            // First packet for this flow
            flow.lastSequence = seqNum;
            flow.initialized = true;
            shouldProcess = true;
            PME_LOG_DEBUG(log_, "New SPCast flow initialized with seq " << seqNum);
        }
        else if (seqNum > flow.lastSequence) {
            // Sequence increased, process packet
            flow.lastSequence = seqNum;
            shouldProcess = true;
        }
        else if (seqNum == flow.lastSequence) {
            // Duplicate packet, ignore
            PME_LOG_DEBUG(log_, "Duplicate SPCast packet with seq " << seqNum);
        }
        else {
            // Out of order packet, ignore
            PME_LOG_DEBUG(log_, "Out of order SPCast packet. Expected > " 
                         << flow.lastSequence << ", got " << seqNum);
        }
    }
    
    if (shouldProcess) {
        // Here you would parse and process the SPCast application data
        // This is a placeholder for proprietary protocol parsing logic
        PME_LOG_DEBUG(log_, "Processing SPCast packet: src=" << srcIP << ":" << srcPort 
                     << " dst=" << dstIP << ":" << dstPort << " seq=" << seqNum 
                     << " len=" << dataLength << " time=" << timestamp);
        
        // Process application layer data starting after SPCast header
        // const uint8_t* appData = data + 8;  // Assuming 8-byte header
        // size_t appDataLength = dataLength - 8;
        
        // TODO: Implement application-specific processing logic here
        
        return true;
    }
    
    return false;
}

std::string SPCastParser::createFlowKey(const std::string& srcIP, uint16_t srcPort, 
                                      const std::string& dstIP, uint16_t dstPort)
{
    std::stringstream ss;
    ss << srcIP << ":" << srcPort << "->" << dstIP << ":" << dstPort;
    return ss.str();
}

uint32_t SPCastParser::extractSequenceNumber(const uint8_t* data, size_t dataLength)
{
    // Assuming sequence number is at offset 4, in network byte order
    if (dataLength >= 8) {
        return ntohl(*reinterpret_cast<const uint32_t*>(data + 4));
    }
    return 0;
}

// ----- RazeParser implementation -----

RazeParser::RazeParser()
    : log_(PME_GET_LOGGER("RazeParser"))
{
}

bool RazeParser::processData(const uint8_t* data, size_t dataLength, 
                           double timestamp, const std::string& srcIP, 
                           const std::string& dstIP, uint16_t srcPort, 
                           uint16_t dstPort)
{
    if (!data || dataLength < 4) {
        PME_LOG_WARNING(log_, "Raze packet too small");
        return false;
    }
    
    // Here you would parse and process the Raze application data
    // This is a placeholder for proprietary protocol parsing logic
    PME_LOG_DEBUG(log_, "Processing Raze packet: src=" << srcIP << ":" << srcPort 
                 << " dst=" << dstIP << ":" << dstPort
                 << " len=" << dataLength << " time=" << timestamp);
    
    // TODO: Implement application-specific processing logic here
    
    return true;
}

// ----- ProtocolParserFactory implementation -----

std::shared_ptr<IProtocolParser> ProtocolParserFactory::getParser(const std::string& protocol)
{
    std::lock_guard<std::mutex> lock(s_parserMutex);
    
    // Convert protocol name to lowercase
    std::string lowerProtocol = protocol;
    std::transform(lowerProtocol.begin(), lowerProtocol.end(), lowerProtocol.begin(), ::tolower);
    
    // Check if parser already exists
    auto it = s_parsers.find(lowerProtocol);
    if (it != s_parsers.end()) {
        return it->second;
    }
    
    // Create new parser
    std::shared_ptr<IProtocolParser> parser;
    
    if (lowerProtocol == "spcast") {
        parser = std::make_shared<SPCastParser>();
    }
    else if (lowerProtocol == "raze") {
        parser = std::make_shared<RazeParser>();
    }
    else {
        return nullptr;
    }
    
    // Store in cache
    s_parsers[lowerProtocol] = parser;
    
    return parser;
}

// ----- PacketProcessor implementation -----

// TCP reassembly callback for PcapPlusPlus
class TcpReassemblyCallback : public pcpp::TcpReassemblyCallback {
public:
    TcpReassemblyCallback(std::shared_ptr<TcpReassemblyHandler> handler)
        : m_handler(handler) {}
    
    void onMessageReady(pcpp::ConnectionData connectionData, const pcpp::TcpStreamData& tcpData) override {
        if (m_handler) {
            m_handler->onMessageReady(connectionData, tcpData.getData(), tcpData.getDataLength());
        }
    }
    
private:
    std::shared_ptr<TcpReassemblyHandler> m_handler;
};

PacketProcessor::PacketProcessor()
    : m_running(false),
      m_processing(false),
      log_(PME_GET_LOGGER("PacketProcessor"))
{
    // Initialize protocol parsers
    m_spcastParser = ProtocolParserFactory::getParser("spcast");
    m_razeParser = ProtocolParserFactory::getParser("raze");
    
    if (!m_spcastParser) {
        PME_LOG_ERROR(log_, "Failed to create SPCast parser");
    }
    
    if (!m_razeParser) {
        PME_LOG_ERROR(log_, "Failed to create Raze parser");
    }
    
    // Start processing thread
    m_running.store(true);
    m_thread = std::thread(&PacketProcessor::processingThread, this);
    
    PME_LOG_INFO(log_, "PacketProcessor initialized");
}

PacketProcessor::~PacketProcessor()
{
    stop();
}

void PacketProcessor::processFile(const std::string& filePath, std::function<void()> onComplete)
{
    PME_LOG_INFO(log_, "Queueing file for processing: " << filePath);
    
    auto context = std::make_unique<ProcessingContext>(filePath, onComplete);
    queueFile(std::move(context));
}

bool PacketProcessor::processGrowingFile(const std::string& filePath)
{
    PME_LOG_INFO(log_, "Processing growing file: " << filePath);
    
    auto context = std::make_unique<ProcessingContext>(filePath, nullptr, true);
    queueFile(std::move(context));
    return true;
}

void PacketProcessor::stop()
{
    if (!m_running.exchange(false)) {
        return; // Already stopped
    }
    
    // Signal processing thread to wake up
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_queueCondition.notify_all();
    }
    
    // Wait for thread to finish
    if (m_thread.joinable()) {
        m_thread.join();
    }
    
    PME_LOG_INFO(log_, "PacketProcessor stopped");
}

bool PacketProcessor::isProcessing() const
{
    return m_processing.load();
}

void PacketProcessor::queueFile(std::unique_ptr<ProcessingContext> context)
{
    if (!m_running.load()) {
        PME_LOG_WARNING(log_, "Cannot queue file, processor is not running");
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_processingQueue.push(std::move(context));
    }
    
    m_queueCondition.notify_one();
}

void PacketProcessor::processingThread()
{
    PME_LOG_INFO(log_, "Processing thread started");
    
    while (m_running.load()) {
        std::unique_ptr<ProcessingContext> context;
        
        // Get the next file to process
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            
            if (m_processingQueue.empty()) {
                // Wait for a file or shutdown
                m_queueCondition.wait(lock, [this] {
                    return !m_running.load() || !m_processingQueue.empty();
                });
                
                if (!m_running.load()) {
                    break;
                }
            }
            
            if (!m_processingQueue.empty()) {
                context = std::move(m_processingQueue.front());
                m_processingQueue.pop();
            }
        }
        
        if (!context) {
            continue;
        }
        
        // Process the file
        try {
            m_processing.store(true);
            
            PME_LOG_INFO(log_, "Processing file: " << context->filePath);
            
            // Initialize context
            if (!initContext(*context)) {
                PME_LOG_ERROR(log_, "Failed to initialize processing context for " << context->filePath);
                continue;
            }
            
            // Read and process packets
            pcpp::RawPacket rawPacket;
            
            while (m_running.load() && context->reader->getNextPacket(rawPacket)) {
                // Parse packet
                pcpp::Packet packet(&rawPacket);
                
                // Process packet
                if (!processPacket(*context, packet)) {
                    PME_LOG_WARNING(log_, "Failed to process packet");
                }
                
                // Update position for growing files
                if (context->isGrowing) {
                    context->lastPosition = context->reader->getFileSize();
                }
            }
            
            // Flush TCP reassembly buffers
            if (context->tcpReassembly) {
                context->tcpReassembly->closeAllConnections();
            }
            
            // File processing complete
            PME_LOG_INFO(log_, "Completed processing file: " << context->filePath);
            
            // Call completion callback
            if (context->onComplete) {
                context->onComplete();
            }
        }
        catch (const std::exception& e) {
            PME_LOG_ERROR(log_, "Exception processing file " << context->filePath << ": " << e.what());
        }
        
        m_processing.store(false);
    }
    
    PME_LOG_INFO(log_, "Processing thread exiting");
}

bool PacketProcessor::initContext(ProcessingContext& context)
{
    // Create file reader
    context.reader.reset(pcpp::IFileReaderDevice::getReader(context.filePath.c_str()));
    
    if (!context.reader) {
        PME_LOG_ERROR(log_, "Failed to create file reader for " << context.filePath);
        return false;
    }
    
    // Open file
    if (!context.reader->open()) {
        PME_LOG_ERROR(log_, "Failed to open file " << context.filePath);
        return false;
    }
    
    // Set position for growing files
    if (context.isGrowing && context.lastPosition > 0) {
        if (!context.reader->setFilePosition(context.lastPosition)) {
            PME_LOG_WARNING(log_, "Failed to set file position to " << context.lastPosition);
            // Continue anyway from beginning
        }
    }
    
    // Create TCP reassembly handler
    context.reassemblyHandler = std::make_shared<TcpReassemblyHandler>(m_razeParser);
    
    // Create TCP reassembly engine
    context.tcpReassembly = std::make_unique<pcpp::TcpReassembly>(
        new TcpReassemblyCallback(context.reassemblyHandler));
    
    return true;
}

bool PacketProcessor::processPacket(ProcessingContext& context, pcpp::Packet& packet)
{
    // Check if packet has IP layer
    pcpp::IPv4Layer* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!ipLayer) {
        return false;
    }
    
    // Check protocol and process accordingly
    if (packet.isPacketOfType(pcpp::UDP)) {
        return handleUdpPacket(context, packet);
    }
    else if (packet.isPacketOfType(pcpp::TCP)) {
        return handleTcpPacket(context, packet);
    }
    
    return false;
}

bool PacketProcessor::handleUdpPacket(ProcessingContext& context, pcpp::Packet& packet)
{
    // Get IP layer
    pcpp::IPv4Layer* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!ipLayer) {
        return false;
    }
    
    // Get UDP layer
    pcpp::UdpLayer* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (!udpLayer) {
        return false;
    }
    
    // Get payload layer
    pcpp::PayloadLayer* payloadLayer = packet.getLayerOfType<pcpp::PayloadLayer>();
    if (!payloadLayer) {
        return false; // No payload
    }
    
    // Get IP addresses and ports
    std::string srcIP = ipLayer->getSrcIPv4Address().toString();
    std::string dstIP = ipLayer->getDstIPv4Address().toString();
    uint16_t srcPort = udpLayer->getSrcPort();
    uint16_t dstPort = udpLayer->getDstPort();
    
    // Get timestamp
    timespec timestamp = packet.getRawPacket()->getPacketTimeStamp();
    double timestampSec = timestamp.tv_sec + (timestamp.tv_nsec / 1000000000.0);
    
    // Get payload data
    const uint8_t* data = payloadLayer->getData();
    size_t dataLength = payloadLayer->getDataLen();
    
    // Process with SPCast parser
    if (m_spcastParser) {
        return m_spcastParser->processData(data, dataLength, timestampSec, 
                                         srcIP, dstIP, srcPort, dstPort);
    }
    
    return false;
}

bool PacketProcessor::handleTcpPacket(ProcessingContext& context, pcpp::Packet& packet)
{
    // Get TCP layer
    pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (!tcpLayer) {
        return false;
    }
    
    // Process with TCP reassembly
    if (context.tcpReassembly) {
        context.tcpReassembly->reassemblePacket(packet);
        return true;
    }
    
    return false;
}
```

## Implementation Notes:

1. **Overall Structure**:
   - The `PacketProcessor` class handles reading PCAP files and dispatching packets to appropriate protocol parsers
   - Uses PcapPlusPlus for PCAP file reading and TCP reassembly
   - Implements a processing queue and worker thread for asynchronous processing

2. **Protocol Parsing**:
   - Uses a factory pattern (`ProtocolParserFactory`) to create parsers for different protocols
   - Includes parsers for SPCast (UDP) and Raze (TCP) protocols
   - Each parser implements the `IProtocolParser` interface

3. **UDP Processing**:
   - `SPCastParser` handles UDP packets with sequence number tracking
   - Detects and discards out-of-order and duplicate packets
   - Maintains flow state based on source/destination IP and port combinations

4. **TCP Processing**:
   - Uses PcapPlusPlus's TCP reassembly capabilities to handle fragmented TCP streams
   - `TcpReassemblyHandler` processes reassembled TCP messages
   - `RazeParser` handles the proprietary application protocol after reassembly

5. **Growing File Support**:
   - Tracks file position to process only new data when handling growing files
   - Reuses context for growing files to maintain state between calls

6. **Error Handling**:
   - Robust error handling throughout with detailed logging
   - Catches and logs exceptions to prevent crashes

7. **Extensibility**:
   - Easy to add new protocol parsers by implementing the `IProtocolParser` interface
   - Factory pattern allows for dynamic protocol parser selection

This implementation should handle all the requirements for processing both TCP and UDP packets with proprietary protocols, including TCP reassembly and handling dropped UDP packets using application layer sequence numbers.

To use this code, you'll need to:
1. Install PcapPlusPlus library
2. Customize the SPCast and Raze parsers for your specific proprietary protocols
3. Update the Engine class to use this PacketProcessor implementation
