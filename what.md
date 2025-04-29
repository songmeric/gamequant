// In MMapHandler.cpp

bool MMapHandler::processFile(const std::string& filePath) {
    PME_LOG_INFO(log_, "MMapHandler::processFile called for " << filePath);
    
    // Clean up previous mapping if any
    unmapCurrentFile();
    
    PME_LOG_INFO(log_, "Processing file: " << filePath);
    
    // Open the file
    m_fd = open(filePath.c_str(), O_RDONLY);
    if (m_fd == -1) {
        PME_LOG_ERROR(log_, "Failed to open file: " << filePath << " - " << strerror(errno));
        return false;
    }
    PME_LOG_DEBUG(log_, "File opened successfully, fd=" << m_fd);
    
    // Get file size
    struct stat sb;
    if (fstat(m_fd, &sb) == -1) {
        PME_LOG_ERROR(log_, "Failed to get file stats: " << strerror(errno));
        close(m_fd);
        m_fd = -1;
        return false;
    }
    
    m_mappedSize = sb.st_size;
    PME_LOG_DEBUG(log_, "File size: " << m_mappedSize << " bytes");
    
    // Check if file is empty
    if (m_mappedSize == 0) {
        PME_LOG_ERROR(log_, "File is empty: " << filePath);
        close(m_fd);
        m_fd = -1;
        return false;
    }
    
    // Map the file - use explicit error check
    m_mappedData = static_cast<uint8_t*>(mmap(nullptr, m_mappedSize, PROT_READ, MAP_PRIVATE, m_fd, 0));
    if (m_mappedData == MAP_FAILED) {
        PME_LOG_ERROR(log_, "Failed to memory map file: " << filePath << " - " << strerror(errno));
        close(m_fd);
        m_fd = -1;
        m_mappedData = nullptr;
        return false;
    }
    
    PME_LOG_DEBUG(log_, "mmap succeeded, address=" << static_cast<const void*>(m_mappedData));
    
    // Check PCAP file header
    if (m_mappedSize < 24) {
        PME_LOG_ERROR(log_, "File too small to be a valid PCAP file");
        unmapCurrentFile();
        return false;
    }
    
    // Validate magic number
    uint32_t magic = *reinterpret_cast<uint32_t*>(m_mappedData);
    PME_LOG_DEBUG(log_, "PCAP magic number: 0x" << std::hex << magic << std::dec);
    
    if (magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1) {
        PME_LOG_ERROR(log_, "Invalid PCAP magic number: 0x" << std::hex << magic << std::dec);
        unmapCurrentFile();
        return false;
    }
    
    m_currentFilePath = filePath;
    PME_LOG_INFO(log_, "Successfully mapped file: " << filePath << " (" << m_mappedSize << " bytes)");
    
    return true;
}

void MMapHandler::unmapCurrentFile() {
    PME_LOG_INFO(log_, "MMapHandler::unmapCurrentFile called");
    
    if (m_mappedData && m_mappedData != MAP_FAILED) {
        PME_LOG_DEBUG(log_, "Unmapping memory at " << static_cast<const void*>(m_mappedData) << ", size=" << m_mappedSize);
        if (munmap(m_mappedData, m_mappedSize) == -1) {
            PME_LOG_ERROR(log_, "Failed to unmap file: " << strerror(errno));
        } else {
            PME_LOG_DEBUG(log_, "Memory unmapped successfully");
        }
        m_mappedData = nullptr;
    } else {
        PME_LOG_DEBUG(log_, "No mapped data to unmap");
    }
    
    if (m_fd != -1) {
        PME_LOG_DEBUG(log_, "Closing file descriptor " << m_fd);
        if (close(m_fd) == -1) {
            PME_LOG_ERROR(log_, "Failed to close file descriptor: " << strerror(errno));
        } else {
            PME_LOG_DEBUG(log_, "File descriptor closed successfully");
        }
        m_fd = -1;
    } else {
        PME_LOG_DEBUG(log_, "No file descriptor to close");
    }
    
    m_mappedSize = 0;
    
    if (!m_currentFilePath.empty()) {
        PME_LOG_INFO(log_, "Unmapped file: " << m_currentFilePath);
        m_currentFilePath.clear();
    } else {
        PME_LOG_DEBUG(log_, "No current file path to clear");
    }
    
    // Notify completion if handler is set
    if (m_completionHandler) {
        PME_LOG_DEBUG(log_, "Calling completion handler");
        m_completionHandler();
    } else {
        PME_LOG_DEBUG(log_, "No completion handler to call");
    }
}
Also, check that the MMapHandler is being properly initialized in the Engine class:
cppCopy// In Engine.cpp, ensure the init() method is correctly creating the MMapHandler

void Engine::init() {
    PME_LOG_INFO(log_, "Initializing engine with input directory: " << m_inputDir);
    
    // Create file handler
    m_fileHandler = std::make_shared<PcapFileHandler>(m_inputDir);
    PME_LOG_DEBUG(log_, "File handler created");
    
    // Create memory map handler
    m_mmapHandler = std::make_shared<MMapHandler>();
    PME_LOG_DEBUG(log_, "Memory map handler created");
    
    // Set up callbacks
    m_fileHandler->setFileTransitionHandler([this](const std::string& filePath) {
        PME_LOG_DEBUG(log_, "File transition callback triggered for: " << filePath);
        onFileReady(filePath);
    });
    
    m_mmapHandler->setCompletionHandler([this]() {
        PME_LOG_DEBUG(log_, "MMap completion callback triggered");
        onFileProcessed();
    });
    
    PME_LOG_INFO(log_, "Engine initialized");
}

void Engine::onFileReady(const std::string& filePath) {
    PME_LOG_INFO(log_, "Processing file: " << filePath);
    
    // Verify m_mmapHandler is not null
    if (!m_mmapHandler) {
        PME_LOG_ERROR(log_, "m_mmapHandler is null in onFileReady");
        return;
    }
    
    // Map the file
    PME_LOG_DEBUG(log_, "Calling m_mmapHandler->processFile for " << filePath);
    if (m_mmapHandler->processFile(filePath)) {
        // Create iterator over the mapped data
        const uint8_t* mappedData = m_mmapHandler->getMappedData();
        size_t mappedSize = m_mmapHandler->getMappedSize();
        
        PME_LOG_DEBUG(log_, "m_mmapHandler returned mappedData=" << static_cast<const void*>(mappedData) 
                   << ", mappedSize=" << mappedSize);
        
        m_iterator = std::make_unique<ThreadSafeIterator>(mappedData, mappedSize);
        
        PME_LOG_INFO(log_, "Created packet iterator for file: " << filePath);
    } else {
        PME_LOG_ERROR(log_, "Failed to process file: " << filePath);
        
        // Mark as processed and move to next
        m_fileHandler->markCurrentFileProcessed();
    }
}
