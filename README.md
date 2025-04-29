I'll start by implementing the PcapFileHandler interface and class following the requested design pattern. Let's begin with the interface header file.
IPcapFileHandler.h
cppCopy#pragma once

#include <string>
#include <functional>

/**
 * Interface for managing PCAP file discovery, selection, and state tracking.
 */
class IPcapFileHandler {
public:
    // File states
    enum class FileState {
        INVALID,     // Not a valid PCAP file
        UNPROCESSED, // Valid but not yet processed
        PROCESSING,  // Currently being processed
        PROCESSED    // Completed processing
    };

    virtual ~IPcapFileHandler() = default;

    // Scan directory for PCAP files
    virtual void scanDirectory() = 0;
    
    // Register callback for when a new file is ready for processing
    virtual void setFileTransitionHandler(std::function<void(const std::string&)> handler) = 0;
    
    // Mark the current file as completely processed
    virtual void markCurrentFileProcessed() = 0;
    
    // Check if there are more files to process
    virtual bool hasMoreFiles() const = 0;
    
    // Get the current file being processed
    virtual std::string getCurrentFilePath() const = 0;
    
    // Get current file state
    virtual FileState getCurrentFileState() const = 0;
};
Now let's implement the concrete PcapFileHandler class:
PcapFileHandler.h
cppCopy#pragma once

#include "IPcapFileHandler.h"
#include "Log.h"
#include <vector>
#include <string>
#include <functional>
#include <mutex>
#include <algorithm>
#include <filesystem>

/**
 * Manages PCAP file discovery, selection, and state tracking.
 */
class PcapFileHandler : public IPcapFileHandler {
public:
    /**
     * Initialize with directory to scan for PCAP files
     * @param directory Path to directory containing PCAP files
     */
    PcapFileHandler(const std::string& directory) 
        : m_directory(directory),
          m_currentFileIndex(-1),
          m_currentState(FileState::INVALID),
          log_(PME_GET_LOGGER("PcapFileHandler")) {
        // Initial scan for files
        scanDirectory();
    }
    
    /**
     * Destructor
     */
    ~PcapFileHandler() = default;
    
    /**
     * Scan or rescan directory for PCAP files
     * Files will be sorted by timestamp (oldest first)
     */
    void scanDirectory() override;
    
    /**
     * Register callback for file transitions
     * @param handler Function to call with file path when a new file is ready
     */
    void setFileTransitionHandler(std::function<void(const std::string&)> handler) override {
        m_transitionHandler = handler;
    }
    
    /**
     * Mark current file as processed and move to next file
     */
    void markCurrentFileProcessed() override;
    
    /**
     * Check if more files are available for processing
     * @return true if there are unprocessed files
     */
    bool hasMoreFiles() const override {
        return m_currentFileIndex < static_cast<int>(m_files.size()) - 1 ||
               (m_currentFileIndex == -1 && !m_files.empty());
    }
    
    /**
     * Get the current file path being processed
     * @return Current file path or empty string if none
     */
    std::string getCurrentFilePath() const override {
        if (m_currentFileIndex >= 0 && m_currentFileIndex < static_cast<int>(m_files.size())) {
            return m_files[m_currentFileIndex];
        }
        return "";
    }
    
    /**
     * Get current file state
     * @return State of the current file
     */
    FileState getCurrentFileState() const override {
        return m_currentState;
    }
    
    /**
     * Start processing the first file
     * Should be called after handlers are set up
     */
    void startProcessing();
    
private:
    // Move to the next file and notify handler
    bool selectNextFile();
    
    // Validate if a file is a valid PCAP file
    bool isValidPcapFile(const std::string& filePath) const;
    
    // Directory to scan
    std::string m_directory;
    
    // List of files (sorted by timestamp)
    std::vector<std::string> m_files;
    
    // Index of current file being processed
    int m_currentFileIndex;
    
    // Current file state
    FileState m_currentState;
    
    // Handler for file transitions
    std::function<void(const std::string&)> m_transitionHandler;
    
    // Mutex for thread safety
    mutable std::mutex m_mutex;
    
    // Logger
    pxx::Log* log_;
};
Now, let's implement the PcapFileHandler class:
PcapFileHandler.cpp
cppCopy#include "PcapFileHandler.h"
#include <pcap/pcap.h>
#include <algorithm>
#include <filesystem>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace fs = std::filesystem;

void PcapFileHandler::scanDirectory() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    PME_LOG_INFO(log_, "Scanning directory: " << m_directory);
    
    std::vector<std::string> newFiles;
    
    try {
        // Check if directory exists
        if (!fs::exists(m_directory) || !fs::is_directory(m_directory)) {
            PME_LOG_ERROR(log_, "Directory does not exist: " << m_directory);
            return;
        }
        
        // Iterate directory and find PCAP files
        for (const auto& entry : fs::directory_iterator(m_directory)) {
            if (entry.is_regular_file()) {
                std::string filePath = entry.path().string();
                
                // Check if it's a valid PCAP file
                if (isValidPcapFile(filePath)) {
                    newFiles.push_back(filePath);
                    PME_LOG_DEBUG(log_, "Found valid PCAP file: " << filePath);
                } else {
                    PME_LOG_DEBUG(log_, "Skipping non-PCAP file: " << filePath);
                }
            }
        }
        
        // Sort files by modification time (oldest first)
        std::sort(newFiles.begin(), newFiles.end(), [](const std::string& a, const std::string& b) {
            return fs::last_write_time(a) < fs::last_write_time(b);
        });
        
        // Update file list
        m_files = std::move(newFiles);
        
        PME_LOG_INFO(log_, "Found " << m_files.size() << " PCAP files in directory");
    } catch (const std::exception& e) {
        PME_LOG_ERROR(log_, "Error scanning directory: " << e.what());
    }
}

bool PcapFileHandler::isValidPcapFile(const std::string& filePath) const {
    // Open the file to check its header
    int fd = open(filePath.c_str(), O_RDONLY);
    if (fd == -1) {
        PME_LOG_ERROR(log_, "Cannot open file: " << filePath << " - " << strerror(errno));
        return false;
    }
    
    // Read the PCAP global header (24 bytes)
    uint8_t header[24];
    ssize_t bytesRead = read(fd, header, sizeof(header));
    close(fd);
    
    if (bytesRead != sizeof(header)) {
        PME_LOG_DEBUG(log_, "File too small to be a PCAP file: " << filePath);
        return false;
    }
    
    // Check magic number (0xa1b2c3d4 or 0xd4c3b2a1)
    uint32_t magic = *reinterpret_cast<uint32_t*>(header);
    if (magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1) {
        PME_LOG_DEBUG(log_, "Invalid PCAP magic number in file: " << filePath);
        return false;
    }
    
    return true;
}

void PcapFileHandler::markCurrentFileProcessed() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_currentFileIndex >= 0 && m_currentFileIndex < static_cast<int>(m_files.size())) {
        PME_LOG_INFO(log_, "Marking file as processed: " << m_files[m_currentFileIndex]);
        m_currentState = FileState::PROCESSED;
        
        // Move to next file
        selectNextFile();
    }
}

bool PcapFileHandler::selectNextFile() {
    // Move to next file
    m_currentFileIndex++;
    
    // Check if we have more files
    if (m_currentFileIndex >= static_cast<int>(m_files.size())) {
        PME_LOG_INFO(log_, "No more files to process");
        m_currentState = FileState::INVALID;
        m_currentFileIndex = -1;
        return false;
    }
    
    // Set current file state
    m_currentState = FileState::UNPROCESSED;
    
    PME_LOG_INFO(log_, "Selected next file: " << m_files[m_currentFileIndex]);
    
    // Notify handler if registered
    if (m_transitionHandler) {
        m_currentState = FileState::PROCESSING;
        m_transitionHandler(m_files[m_currentFileIndex]);
    }
    
    return true;
}

void PcapFileHandler::startProcessing() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_files.empty()) {
        PME_LOG_INFO(log_, "No files to process");
        return;
    }
    
    // Reset current index and start with first file
    m_currentFileIndex = -1;
    selectNextFile();
}
Now, let's create the MMapHandler interface and implementation:
IMMapHandler.h
cppCopy#pragma once

#include <string>
#include <functional>
#include <cstdint>

/**
 * Interface for memory mapping PCAP files
 */
class IMMapHandler {
public:
    virtual ~IMMapHandler() = default;
    
    // Process a file by memory mapping it
    virtual bool processFile(const std::string& filePath) = 0;
    
    // Clean up current mapping
    virtual void unmapCurrentFile() = 0;
    
    // Get access to mapped data
    virtual const uint8_t* getMappedData() const = 0;
    virtual size_t getMappedSize() const = 0;
    
    // Register completion handler
    virtual void setCompletionHandler(std::function<void()> handler) = 0;
};
Now, let's implement the MMapHandler class:
MMapHandler.h
cppCopy#pragma once

#include "IMMapHandler.h"
#include "Log.h"
#include <string>
#include <functional>
#include <cstdint>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

/**
 * Handles memory mapping of PCAP files
 */
class MMapHandler : public IMMapHandler {
public:
    /**
     * Constructor
     */
    MMapHandler() 
        : m_fd(-1), 
          m_mappedData(nullptr), 
          m_mappedSize(0),
          log_(PME_GET_LOGGER("MMapHandler")) {
    }
    
    /**
     * Destructor - ensures resources are cleaned up
     */
    ~MMapHandler() {
        unmapCurrentFile();
    }
    
    /**
     * Process a file by memory mapping it
     * @param filePath Path to the PCAP file
     * @return true if successful, false on error
     */
    bool processFile(const std::string& filePath) override;
    
    /**
     * Clean up current mapping
     */
    void unmapCurrentFile() override;
    
    /**
     * Get pointer to mapped data
     * @return Pointer to the memory-mapped data or nullptr if not mapped
     */
    const uint8_t* getMappedData() const override {
        return m_mappedData;
    }
    
    /**
     * Get size of mapped data
     * @return Size of the memory-mapped data in bytes
     */
    size_t getMappedSize() const override {
        return m_mappedSize;
    }
    
    /**
     * Register completion handler
     * @param handler Function to call when processing is complete
     */
    void setCompletionHandler(std::function<void()> handler) override {
        m_completionHandler = handler;
    }
    
private:
    // Current file descriptor
    int m_fd;
    
    // Mapped memory
    uint8_t* m_mappedData;
    
    // Size of mapped data
    size_t m_mappedSize;
    
    // Current file path
    std::string m_currentFilePath;
    
    // Completion handler
    std::function<void()> m_completionHandler;
    
    // Logger
    pxx::Log* log_;
};
MMapHandler.cpp
cppCopy#include "MMapHandler.h"
#include <sys/stat.h>
#include <cstring>

bool MMapHandler::processFile(const std::string& filePath) {
    // Clean up previous mapping if any
    unmapCurrentFile();
    
    PME_LOG_INFO(log_, "Processing file: " << filePath);
    
    // Open the file
    m_fd = open(filePath.c_str(), O_RDONLY);
    if (m_fd == -1) {
        PME_LOG_ERROR(log_, "Failed to open file: " << filePath << " - " << strerror(errno));
        return false;
    }
    
    // Get file size
    struct stat sb;
    if (fstat(m_fd, &sb) == -1) {
        PME_LOG_ERROR(log_, "Failed to get file stats: " << strerror(errno));
        close(m_fd);
        m_fd = -1;
        return false;
    }
    
    m_mappedSize = sb.st_size;
    
    // Check if file is empty
    if (m_mappedSize == 0) {
        PME_LOG_ERROR(log_, "File is empty: " << filePath);
        close(m_fd);
        m_fd = -1;
        return false;
    }
    
    // Map the file
    m_mappedData = static_cast<uint8_t*>(mmap(nullptr, m_mappedSize, PROT_READ, MAP_PRIVATE, m_fd, 0));
    if (m_mappedData == MAP_FAILED) {
        PME_LOG_ERROR(log_, "Failed to memory map file: " << strerror(errno));
        close(m_fd);
        m_fd = -1;
        m_mappedData = nullptr;
        return false;
    }
    
    // Check PCAP file header
    if (m_mappedSize < 24) {
        PME_LOG_ERROR(log_, "File too small to be a valid PCAP file");
        unmapCurrentFile();
        return false;
    }
    
    // Validate magic number
    uint32_t magic = *reinterpret_cast<uint32_t*>(m_mappedData);
    if (magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1) {
        PME_LOG_ERROR(log_, "Invalid PCAP magic number: " << std::hex << magic);
        unmapCurrentFile();
        return false;
    }
    
    m_currentFilePath = filePath;
    PME_LOG_INFO(log_, "Successfully mapped file: " << filePath << " (" << m_mappedSize << " bytes)");
    
    return true;
}

void MMapHandler::unmapCurrentFile() {
    if (m_mappedData) {
        if (munmap(m_mappedData, m_mappedSize) == -1) {
            PME_LOG_ERROR(log_, "Failed to unmap file: " << strerror(errno));
        }
        m_mappedData = nullptr;
    }
    
    if (m_fd != -1) {
        if (close(m_fd) == -1) {
            PME_LOG_ERROR(log_, "Failed to close file: " << strerror(errno));
        }
        m_fd = -1;
    }
    
    m_mappedSize = 0;
    
    if (!m_currentFilePath.empty()) {
        PME_LOG_INFO(log_, "Unmapped file: " << m_currentFilePath);
        m_currentFilePath.clear();
    }
    
    // Notify completion if handler is set
    if (m_completionHandler) {
        m_completionHandler();
    }
}
Now, let's create the PcapPacketIterator to safely iterate through packets:
PcapPacketIterator.h
cppCopy#pragma once

#include <cstdint>
#include <chrono>
#include <utility>
#include <string>
#include "Log.h"

/**
 * Safely iterates through packets in a memory-mapped PCAP file
 */
class PcapPacketIterator {
public:
    // Packet validation state
    enum class PacketState {
        VALID,           // Packet is valid and ready for processing
        END_OF_FILE,     // No more packets in file
        CORRUPT_HEADER,  // Packet header is corrupt
        TRUNCATED,       // Packet data is truncated
        OUT_OF_BOUNDS    // Packet would exceed file bounds
    };
    
    // View into a packet in memory
    struct PacketView {
        const uint8_t* headerStart;   // Start of packet header
        const uint8_t* dataStart;     // Start of packet data
        uint32_t headerSize;          // Size of header
        uint32_t dataSize;            // Size of data
        uint32_t originalSize;        // Original size on wire
        std::chrono::system_clock::time_point timestamp;
    };
    
    /**
     * Constructor - initializes iterator over memory-mapped PCAP data
     * @param mappedData Pointer to memory-mapped PCAP file
     * @param fileSize Size of the mapped data
     */
    PcapPacketIterator(const uint8_t* mappedData, size_t fileSize) 
        : m_mappedData(mappedData),
          m_fileSize(fileSize),
          m_currentPos(mappedData + 24),  // Skip global header
          m_packetCount(0),
          m_needsByteSwap(checkByteSwap(mappedData)),
          log_(PME_GET_LOGGER("PcapPacketIterator")) {
        
        PME_LOG_INFO(log_, "Created packet iterator with " 
                   << fileSize << " bytes of data, byte swap: " 
                   << (m_needsByteSwap ? "yes" : "no"));
    }
    
    /**
     * Default destructor
     */
    ~PcapPacketIterator() = default;
    
    /**
     * Move to next packet and validate it
     * @return Pair containing packet state and view (view is valid only if state is VALID)
     */
    std::pair<PacketState, PacketView> next();
    
    /**
     * Get number of packets processed so far
     */
    size_t getPacketCount() const {
        return m_packetCount;
    }
    
private:
    // Check if byte swapping is needed based on magic number
    bool checkByteSwap(const uint8_t* data) const {
        uint32_t magic = *reinterpret_cast<const uint32_t*>(data);
        return (magic == 0xd4c3b2a1);  // Little endian on big endian system
    }
    
    // Swap byte order for 32-bit value if needed
    uint32_t swapIfNeeded(uint32_t value) const {
        if (m_needsByteSwap) {
            return ((value & 0xFF) << 24) | 
                   ((value & 0xFF00) << 8) | 
                   ((value & 0xFF0000) >> 8) | 
                   ((value & 0xFF000000) >> 24);
        }
        return value;
    }
    
    // Pointer to memory-mapped data
    const uint8_t* m_mappedData;
    
    // Size of memory-mapped data
    size_t m_fileSize;
    
    // Current position in data
    const uint8_t* m_currentPos;
    
    // Number of packets processed
    size_t m_packetCount;
    
    // Whether byte swapping is needed
    bool m_needsByteSwap;
    
    // Logger
    pxx::Log* log_;
};
PcapPacketIterator.cpp
cppCopy#include "PcapPacketIterator.h"
#include <sstream>

std::pair<PcapPacketIterator::PacketState, PcapPacketIterator::PacketView> PcapPacketIterator::next() {
    // Check if we've reached the end of the file
    if (m_currentPos >= m_mappedData + m_fileSize) {
        return {PacketState::END_OF_FILE, {}};
    }
    
    // Check if we have enough space for a packet header (16 bytes)
    if (m_currentPos + 16 > m_mappedData + m_fileSize) {
        PME_LOG_WARNING(log_, "Truncated packet header at offset " 
                      << (m_currentPos - m_mappedData));
        return {PacketState::TRUNCATED, {}};
    }
    
    // Read packet header fields
    uint32_t ts_sec = swapIfNeeded(*reinterpret_cast<const uint32_t*>(m_currentPos));
    uint32_t ts_usec = swapIfNeeded(*reinterpret_cast<const uint32_t*>(m_currentPos + 4));
    uint32_t caplen = swapIfNeeded(*reinterpret_cast<const uint32_t*>(m_currentPos + 8));
    uint32_t origlen = swapIfNeeded(*reinterpret_cast<const uint32_t*>(m_currentPos + 12));
    
    // Validate reasonable sizes (sanity check)
    if (caplen > 65535 || origlen > 65535 || caplen > origlen) {
        std::stringstream ss;
        ss << "Suspicious packet sizes at offset " << (m_currentPos - m_mappedData)
           << ": caplen=" << caplen << ", origlen=" << origlen;
        PME_LOG_WARNING(log_, ss.str());
        
        // Skip this packet header and try to recover
        m_currentPos += 16;
        return {PacketState::CORRUPT_HEADER, {}};
    }
    
    // Check if packet data fits in the file
    if (m_currentPos + 16 + caplen > m_mappedData + m_fileSize) {
        PME_LOG_WARNING(log_, "Truncated packet data at offset " 
                      << (m_currentPos - m_mappedData));
        return {PacketState::TRUNCATED, {}};
    }
    
    // Create packet view
    PacketView view;
    view.headerStart = m_currentPos;
    view.dataStart = m_currentPos + 16;
    view.headerSize = 16;
    view.dataSize = caplen;
    view.originalSize = origlen;
    
    // Convert timestamp
    view.timestamp = std::chrono::system_clock::from_time_t(ts_sec) + 
                    std::chrono::microseconds(ts_usec);
    
    // Advance position for next packet
    m_currentPos += 16 + caplen;
    m_packetCount++;
    
    return {PacketState::VALID, view};
}
Now, let's create a ThreadSafeIterator wrapper:
ThreadSafeIterator.h
cppCopy#pragma once

#include "PcapPacketIterator.h"
#include <mutex>

/**
 * Thread-safe wrapper around PcapPacketIterator
 */
class ThreadSafeIterator {
public:
    /**
     * Constructor - initializes the wrapped iterator
     * @param mappedData Pointer to memory-mapped PCAP file
     * @param fileSize Size of the mapped data
     */
    ThreadSafeIterator(const uint8_t* mappedData, size_t fileSize)
        : m_iterator(mappedData, fileSize) {
    }
    
    /**
     * Get next packet in a thread-safe manner
     * @return Pair containing packet state and view
     */
    std::pair<PcapPacketIterator::PacketState, PcapPacketIterator::PacketView> next() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_iterator.next();
    }
    
    /**
     * Get packet count in a thread-safe manner
     * @return Number of packets processed
     */
    size_t getPacketCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_iterator.getPacketCount();
    }
    
private:
    // Wrapped iterator
    PcapPacketIterator m_iterator;
    
    // Mutex for thread safety
    mutable std::mutex m_mutex;
};
Finally, let's update the Engine class to use our new components:
Engine.h
cppCopy#pragma once

#include "IPcapFileHandler.h"
#include "IMMapHandler.h"
#include "ThreadSafeIterator.h"
#include "Log.h"
#include <memory>
#include <string>
#include <atomic>
#include <chrono>

/**
 * Core engine that orchestrates the packet processing pipeline
 */
class Engine {
public:
    /**
     * Constructor
     * @param inputDir Directory containing PCAP files to process
     */
    Engine(const std::string& inputDir) 
        : m_inputDir(inputDir),
          m_shutdown(false),
          log_(PME_GET_LOGGER("Engine")) {
    }
    
    /**
     * Destructor
     */
    ~Engine() {
        stop();
    }
    
    /**
     * Initialize the engine components
     */
    void init();
    
    /**
     * Start the engine
     */
    void start();
    
    /**
     * Stop the engine
     */
    void stop();
    
    /**
     * Check if the engine should stop
     */
    bool shouldStop() const {
        return m_shutdown.load(std::memory_order_relaxed);
    }
    
    /**
     * Main engine loop
     */
    void run();
    
private:
    // Handle file transitions
    void onFileReady(const std::string& filePath);
    
    // Handle file processing completion
    void onFileProcessed();
    
    // Process packets from the current file
    void processCurrentFile();
    
    // Input directory
    std::string m_inputDir;
    
    // Components
    std::shared_ptr<IPcapFileHandler> m_fileHandler;
    std::shared_ptr<IMMapHandler> m_mmapHandler;
    std::unique_ptr<ThreadSafeIterator> m_iterator;
    
    // State
    std::atomic<bool> m_shutdown;
    
    // Logger
    pxx::Log* log_;
};
Engine.cpp
cppCopy#include "Engine.h"
#include "PcapFileHandler.h"
#include "MMapHandler.h"
#include <iostream>
#include <thread>

void Engine::init() {
    PME_LOG_INFO(log_, "Initializing engine with input directory: " << m_inputDir);
    
    // Create file handler
    m_fileHandler = std::make_shared<PcapFileHandler>(m_inputDir);
    
    // Create memory map handler
    m_mmapHandler = std::make_shared<MMapHandler>();
    
    // Set up callbacks
    m_fileHandler->setFileTransitionHandler([this](const std::string& filePath) {
        onFileReady(filePath);
    });
    
    m_mmapHandler->setCompletionHandler([this]() {
        onFileProcessed();
    });
    
    PME_LOG_INFO(log_, "Engine initialized");
}

void Engine::start() {
    PME_LOG_INFO(log_, "Starting engine");
    
    // Ensure components are initialized
    if (!m_fileHandler || !m_mmapHandler) {
        init();
    }
    
    // Start file processing
    static_cast<PcapFileHandler*>(m_fileHandler.get())->startProcessing();
    
    PME_LOG_INFO(log_, "Engine started");
}

void Engine::stop() {
    PME_LOG_INFO(log_, "Stopping engine");
    
    // Set shutdown flag
    m_shutdown.store(true, std::memory_order_relaxed);
    
    // Clean up resources
    if (m_mmapHandler) {
        m_mmapHandler->unmapCurrentFile();
    }
    
    // Clear iterator
    m_iterator.reset();
    
    PME_LOG_INFO(log_, "Engine stopped");
}

void Engine::run() {
    PME_LOG_INFO(log_, "Engine running");
    
    try {
        while (!shouldStop()) {
            // Process current file if we have one
            if (m_iterator) {
                processCurrentFile();
            } else {
                // No active file, sleep briefly to avoid busy-waiting
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    } catch (const std::exception& e) {
        PME_LOG_FATAL(log_, "Exception in engine loop: " << e.what());
        stop();
    }
}

void Engine::onFileReady(const std::string& filePath) {
    PME_LOG_INFO(log_, "Processing file: " << filePath);
    
    // Map the file
    if (m_mmapHandler->processFile(filePath)) {
        // Create iterator over the mapped data
        m_iterator = std::make_unique<ThreadSafeIterator>(
            m_mmapHandler->getMappedData(),
            m_mmapHandler->getMappedSize()
        );
        
        PME_LOG_INFO(log_, "Created packet iterator for file: " << filePath);
    } else {
        PME_LOG_ERROR(log_, "Failed to process file: " << filePath);
        
        // Mark as processed and move to next
        m_fileHandler->markCurrentFileProcessed();
    }
}

void Engine::onFileProcessed() {
    PME_LOG_INFO(log_, "File processing complete");
    
    // Clear iterator
    m_iterator.reset();
    
    // Mark current file as processed and move to next
    m_fileHandler->markCurrentFileProcessed();
}

void Engine::processCurrentFile() {
    // Simple test to iterate through packets
    PcapPacketIterator::PacketState state;
    PcapPacketIterator::PacketView view;
    
    // Get next packet
    std::tie(state, view) = m_iterator->next();
    
    switch (state) {
        case PcapPacketIterator::PacketState::VALID:
            // Process packet here (just logging for now)
            if (m_iterator->getPacketCount() % 1000 == 0) {
                PME_LOG_INFO(log_, "Processed " << m_iterator->getPacketCount() << " packets");
            }
            break;
            
        case PcapPacketIterator::PacketState::END_OF_FILE:
            PME_LOG_INFO(log_, "Reached end of file, processed " 
                       << m_iterator->getPacketCount() << " packets");
            // Clean up and mark file as processed
            m_mmapHandler->unmapCurrentFile();
            break;
            
        case PcapPacketIterator::PacketState::CORRUPT_HEADER:
        case PcapPacketIterator::PacketState::TRUNCATED:
        case PcapPacketIterator::PacketState::OUT_OF_BOUNDS:
            PME_LOG_WARNING(log_, "Encountered invalid packet with state: " 
                          << static_cast<int>(state));
            break;
    }
}
Finally, let's update main.cpp to use our new components:
main.cpp
cppCopy#include <iostream>
#include <cstdlib>
#include <csignal>
#include "Engine.h"
#include "Log.h"
#include <spapp/logging/logging.hpp>

// Global engine pointer for signal handling
static std::shared_ptr<Engine> g_engine;
static std::atomic<bool> g_running(true);
pxx::Log* log_(PME_GET_LOGGER("main"));

// Signal handler
void signalHandler(int signal) {
    PME_LOG_INFO(log_, "Received signal " << signal << ", initiating shutdown");
    g_running = false;
    
    if (g_engine) {
        g_engine->stop();
    }
}

int main(int argc, char** argv) {
    // Set up signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    // Default input directory
    std::string inputDir = "/lhome/songjoon/SBS/pme/tests/pcaps";
    
    // Override from arguments if provided
    if (argc > 1) {
        inputDir = argv[1];
    }
    
    // Initialize logging
    spapp::logging::start(spapp::logging::stdout_config());
    
    try {
        PME_LOG_INFO(log_, "Creating Packet Matching Engine");
        g_engine = std::make_shared<Engine>(inputDir);
        
        PME_LOG_INFO(log_, "Engine created");
        
        // Initialize and start the engine
        g_engine->init();
        PME_LOG_INFO(log_, "Engine initialized");
        
        g_engine->start();
        PME_LOG_INFO(log_, "Engine started");
        
        // Run the engine
        g_engine->run();
    }
    catch (const std::exception& e) {
        PME_LOG_ERROR(log_, "Error: " << e.what());
        return 1;
    }
    
    // Clean shutdown
    spapp::logging::stop();
    return 0;
}
This implementation includes:

IPcapFileHandler/PcapFileHandler - Interface and class to manage PCAP file discovery and selection
IMMapHandler/MMapHandler - Interface and class to handle memory mapping of PCAP files
PcapPacketIterator - Class to safely iterate through packets in a memory-mapped PCAP file
ThreadSafeIterator - Thread-safe wrapper around PcapPacketIterator
Engine - Coordinates the overall process
main.cpp - Entry point with signal handling

The code follows the requested design pattern with interface header files (.h) separate from implementation headers, and with constructors/destructors implemented in the header files. The implementation focuses on safely handling PCAP files, memory mapping them, and iterating through packets with proper error handling.Add to Conversation
