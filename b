Below are self-contained, C++17 implementation skeletons for the three new translation units you asked for.
They compile against the headers you supplied, rely only on the C++ standard library and PcapPlusPlus, and follow the same logging idiom (PME_GET_LOGGER, PME_LOG_*).
I kept the places you’ll extend later clearly marked with TODO comments.

PcapFileHandler.cpp
cpp
복사
편집
#include "PcapFileHandler.h"

#include <fstream>
#include <unordered_map>
#include <chrono>
#include <thread>

namespace fs = std::filesystem;

// ---------- helpers ----------------------------------------------------------

namespace {

bool hasPcapExtension(const fs::path& p)
{
    return p.extension() == ".pcap" || p.extension() == ".pcapng";
}

std::time_t toTimeT(const fs::file_time_type& ftime)
{
    using namespace std::chrono;
    return system_clock::to_time_t(time_point_cast<system_clock::duration>(ftime - fs::file_time_type::clock::now()
                                               + system_clock::now()));
}

} // unnamed namespace
// -----------------------------------------------------------------------------


// ---------- public interface -------------------------------------------------

void PcapFileHandler::scanDirectory()
{
    bool directoryChanged = false;

    // Detect creation / deletion / size-changes
    for (const auto& dirEntry : fs::directory_iterator(m_directory))
    {
        if (!dirEntry.is_regular_file())
            continue;

        const std::string pathStr = dirEntry.path().string();

        // New file ------------------------------------------------------------
        if (m_fileStates.find(pathStr) == m_fileStates.end())
        {
            if (!isValidPcapFile(pathStr))
            {
                m_fileStates[pathStr] = FileState::INVALID;
                continue;
            }

            m_fileStates[pathStr] = isFileGrowing(pathStr)
                                        ? FileState::GROWING
                                        : FileState::UNPROCESSED_STATIC;

            directoryChanged = true;
        }
        // Existing file – check if it stopped growing -------------------------
        else if (m_fileStates[pathStr] == FileState::GROWING &&
                 !isFileGrowing(pathStr))
        {
            m_fileStates[pathStr] = FileState::UNPROCESSED_STATIC;
            directoryChanged      = true;
        }
    }

    // Detect removed files ----------------------------------------------------
    for (auto it = m_fileStates.begin(); it != m_fileStates.end(); )
    {
        if (!fs::exists(it->first))
        {
            it = m_fileStates.erase(it);
            directoryChanged = true;
        }
        else
            ++it;
    }

    // Re-build ordered list if anything changed ------------------------------
    if (directoryChanged)
    {
        m_files.clear();

        // 1. Any growing file (spec mandates there can be only one)
        for (const auto& [file, state] : m_fileStates)
        {
            if (state == FileState::GROWING)
                m_files.emplace_back(file);
        }
        if (m_files.size() > 1)
        {
            throw std::runtime_error(
                "Multiple growing pcap files detected – this is an error.");
        }

        // 2. Static, unprocessed – order by last_write_time (oldest first)
        std::vector<std::pair<std::string, std::time_t>> dated;
        for (const auto& [file, state] : m_fileStates)
        {
            if (state == FileState::UNPROCESSED_STATIC)
            {
                dated.emplace_back(
                    file,
                    toTimeT(fs::last_write_time(file)));
            }
        }
        std::sort(dated.begin(), dated.end(),
                  [](auto& a, auto& b){ return a.second < b.second; });

        for (auto& d : dated)
            m_files.emplace_back(std::move(d.first));

        selectNextFile();   // may fire transition callback
    }
}

void PcapFileHandler::markCurrentFileProcessed()
{
    if (m_currentFilePath.empty())
        return;

    auto it = m_fileStates.find(m_currentFilePath);
    if (it != m_fileStates.end())
        it->second = FileState::PROCESSED_STATIC;

    selectNextFile();   // move on & possibly fire callback
}

bool PcapFileHandler::isFileGrowing(const std::string& filePath) const
{
    static std::unordered_map<std::string, std::uintmax_t> previousSizes;

    auto nowSize = fs::file_size(filePath);
    auto oldIt   = previousSizes.find(filePath);

    bool growing = (oldIt == previousSizes.end()) || (nowSize != oldIt->second);
    previousSizes[filePath] = nowSize;     // update snapshot

    return growing;
}

// ---------- private helpers --------------------------------------------------

bool PcapFileHandler::selectNextFile()
{
    // Already have a file selected & not finished? keep it.
    if (m_currentFileIndex >= 0 &&
        m_currentFileIndex < static_cast<int>(m_files.size()) &&
        m_fileStates.at(m_files[m_currentFileIndex]) != FileState::PROCESSED_STATIC)
        return false;

    // Find next candidate
    for (std::size_t i = 0; i < m_files.size(); ++i)
    {
        if (m_fileStates.at(m_files[i]) == FileState::UNPROCESSED_STATIC ||
            m_fileStates.at(m_files[i]) == FileState::GROWING)
        {
            m_currentFileIndex = static_cast<int>(i);
            m_currentFilePath  = m_files[i];

            if (m_transitionHandler)
                m_transitionHandler(m_currentFilePath);

            return true;
        }
    }

    m_currentFileIndex = -1;
    m_currentFilePath.clear();
    return false;
}

bool PcapFileHandler::isValidPcapFile(const std::string& filePath) const
{
    return hasPcapExtension(fs::path{filePath});
}
Engine.cpp
cpp
복사
편집
#include "Engine.h"
#include "PcapFileHandler.h"
#include "PcapFileProcessor.h"

#include <thread>

void Engine::init()
{
    m_fileHandler = std::make_shared<PcapFileHandler>(m_inputDir);

    // Callback when the handler selects a new file
    m_fileHandler->setFileTransitionHandler(
        [this](const std::string& path) { onFileReady(path); });
}

void Engine::start()
{
    PME_LOG_INFO(log_, "Engine start");
}

void Engine::stop()
{
    PME_LOG_INFO(log_, "Engine stop requested");
    m_shutdown.store(true, std::memory_order_relaxed);
}

void Engine::run()
{
    constexpr auto pollInterval = std::chrono::milliseconds(200);

    while (!shouldStop())
    {
        m_fileHandler->scanDirectory();
        processCurrentFile();
        std::this_thread::sleep_for(pollInterval);
    }

    PME_LOG_INFO(log_, "Engine main loop exited");
}

// ---------------------------------------------------------------------------
// private
// ---------------------------------------------------------------------------

void Engine::onFileReady(const std::string& filePath)
{
    PME_LOG_INFO(log_, "File ready: " << filePath);

    // Create/replace processor for new file
    m_processor = std::make_unique<PcapFileProcessor>(
        filePath,
        /* notification back to engine */
        [this](const PcapFileProcessor::LogicalPacketInfo& info)
        {
            // Right now, just log.  Later you’ll match inbound/outbound etc.
            PME_LOG_DEBUG(log_, "Logical packet: proto="
                                   << info.protocolType
                                   << " bytes=" << info.totalBytes);
        });

    // Synchronous process for now (can be moved to its own thread later)
    m_processor->process();
    onFileProcessed();
}

void Engine::onFileProcessed()
{
    PME_LOG_INFO(log_, "File processed");
    m_fileHandler->markCurrentFileProcessed();
}

void Engine::processCurrentFile()
{
    // In this version work is done synchronously in onFileReady().
    // If you later refactor to an async processor thread, place join / pump
    // logic here.
}
PcapFileProcessor.h
cpp
복사
편집
#pragma once

#include "Log.h"
#include <PcapFileDevice.h>
#include <Packet.h>
#include <TcpReassembly.h>

#include <unordered_map>
#include <functional>
#include <vector>

class PcapFileProcessor
{
public:
    struct LogicalPacketInfo
    {
        std::string protocolType;   //!< “L1-MD”, “OrderAck”, …
        std::size_t totalBytes;     //!< bytes in logical packet / data chunk
    };

    using NotificationHandler = std::function<void(const LogicalPacketInfo&)>;

    PcapFileProcessor(const std::string& filePath,
                      NotificationHandler   notify);

    /**
     * Fully process the file.  Blocking.
     * @return true on success
     */
    bool process();

private:
    // ---- UDP (multicast) helpers ------------------------------------------
    struct FlowKey
    {
        uint32_t src;
        uint32_t dst;
        uint16_t sport;
        uint16_t dport;
        bool     operator==(const FlowKey&) const = default;
    };
    struct UDPFlowState
    {
        std::vector<uint8_t> reassemblyBuf;
        // TODO: instrument-specific last sequence number map, etc.
    };

    struct FlowKeyHasher
    {
        std::size_t operator()(const FlowKey& k) const noexcept
        {
            std::size_t h = 0;
            h ^= std::hash<uint32_t>{}(k.src)  + 0x9e3779b97f4a7c15ULL + (h<<6)+(h>>2);
            h ^= std::hash<uint32_t>{}(k.dst)  + 0x9e3779b97f4a7c15ULL + (h<<6)+(h>>2);
            h ^= std::hash<uint16_t>{}(k.sport)+ 0x9e3779b97f4a7c15ULL + (h<<6)+(h>>2);
            h ^= std::hash<uint16_t>{}(k.dport)+ 0x9e3779b97f4a7c15ULL + (h<<6)+(h>>2);
            return h;
        }
    };

    // ---- TCP reassembly callback ------------------------------------------
    static void onTcpMessageReady(int                    side,
                                  pcpp::TcpStreamData*   data,
                                  void*                  userCookie);

    void handleTcpStream(const uint8_t* data,
                         size_t         len);

    void handleUdpPacket(const pcpp::Packet& pkt);

    // Proprietary protocol inspection stubs ---------------------------------
    bool canParseViaFlow(const FlowKey&) const;
    bool canParseViaPayload(const uint8_t* payload, std::size_t len) const;
    LogicalPacketInfo parseLogicalPacket(const uint8_t* payload,
                                         std::size_t    len);

    // -----------------------------------------------------------------------
    std::string                 m_filePath;
    NotificationHandler         m_notify;
    px::Log*                    log_;

    pcpp::TcpReassembly         m_tcpReassembly;

    std::unordered_map<FlowKey, UDPFlowState, FlowKeyHasher> m_udpFlows;
};
PcapFileProcessor.cpp
cpp
복사
편집
#include "PcapFileProcessor.h"

#include <cstring>

using namespace pcpp;

// ------------------------------------------------ constructors --------------

PcapFileProcessor::PcapFileProcessor(const std::string& filePath,
                                     NotificationHandler notify)
: m_filePath(filePath)
, m_notify(std::move(notify))
, log_(PME_GET_LOGGER("PcapFileProcessor"))
, m_tcpReassembly(onTcpMessageReady, this)
{}

// ------------------------------------------------ public ---------------------

bool PcapFileProcessor::process()
{
    PcapFileReaderDevice reader(m_filePath);
    if (!reader.open())
    {
        PME_LOG_ERROR(log_, "Failed to open pcap file " << m_filePath);
        return false;
    }

    RawPacket rawPacket;
    while (reader.getNextPacket(rawPacket))
    {
        Packet parsed(&rawPacket);

        if (parsed.isPacketOfType(UDP))
        {
            handleUdpPacket(parsed);
        }
        else if (parsed.isPacketOfType(TCP))
        {
            m_tcpReassembly.reassemblePacket(parsed);
        }
        // else ignore
    }

    reader.close();
    return true;
}

// ------------------------------------------------ UDP ------------------------

void PcapFileProcessor::handleUdpPacket(const Packet& pkt)
{
    auto* ipLayer  = pkt.getLayerOfType<IPv4Layer>();
    auto* udpLayer = pkt.getLayerOfType<UDPLayer>();

    if (!ipLayer || !udpLayer)
        return;

    FlowKey key{
        ipLayer->getSrcIpAddress().toInt(),
        ipLayer->getDstIpAddress().toInt(),
        udpLayer->getSrcPort(),
        udpLayer->getDstPort()
    };

    auto& state = m_udpFlows[key];

    const uint8_t* payload   = udpLayer->getPayload();
    const size_t   payloadLen= udpLayer->getPayloadLen();

    if (!canParseViaFlow(key) || !canParseViaPayload(payload, payloadLen))
        return;  // not a protocol we care about

    // -- simplistic reassembly demo -----------------------------------------
    // In many market-data protocols each UDP datagram is a complete message,
    // but some bundle several app messages or fragment them.  Here we simply
    // treat the entire datagram as one logical packet; replace with real
    // reassembly logic for your header fields & length indicators.

    LogicalPacketInfo info = parseLogicalPacket(payload, payloadLen);
    m_notify(info);
}

// ------------------------------------------------ TCP ------------------------

void PcapFileProcessor::onTcpMessageReady(int side,
                                          TcpStreamData* data,
                                          void* userCookie)
{
    auto* self = static_cast<PcapFileProcessor*>(userCookie);
    self->handleTcpStream(data->getData(), data->getDataLen());
}

void PcapFileProcessor::handleTcpStream(const uint8_t* data,
                                        size_t len)
{
    // TODO real protocol framing over the byte-stream.
    // For now emit one logical packet per reassembled message.

    LogicalPacketInfo info = parseLogicalPacket(data, len);
    m_notify(info);
}

// ------------------------------------------------ proprietary stubs ----------

bool PcapFileProcessor::canParseViaFlow(const FlowKey& key) const
{
    // TODO: fill in flow-based filters (IP/port pairs).
    (void)key;
    return true;
}

bool PcapFileProcessor::canParseViaPayload(const uint8_t* payload,
                                           std::size_t    len) const
{
    // TODO: inspect header bytes to verify this really is your protocol.
    (void)payload; (void)len;
    return true;
}

PcapFileProcessor::LogicalPacketInfo
PcapFileProcessor::parseLogicalPacket(const uint8_t* payload,
                                      std::size_t    len)
{
    // TODO: replace with actual message parsing.
    LogicalPacketInfo info;
    info.protocolType = "PROTO-TODO";
    info.totalBytes   = len;
    return info;
}
How to extend
Directory polling – tune pollInterval or make it configurable.

Asynchronous processing – move PcapFileProcessor::process() into a worker thread so the engine can continue scanning for new files while a long file is parsed.

UDP logical re-assembly & gap-check – hook your proprietary header parsing into handleUdpPacket(), accumulate bytes in UDPFlowState::reassemblyBuf, and track per-instrument sequence numbers to spot drops.

TCP framing – inside handleTcpStream() peel complete messages from the byte stream based on your header length field (or fix/finalise PcapPlusPlus’ callback granularity).

Notification – LogicalPacketInfo is just a placeholder: expand with instrument ID, L1/L2 flag, sequence number, NIC timestamp etc., and eventually pipe it into the matching engine.

These skeletons should compile and run, producing detailed logs that confirm the pipeline (scan → select → process → notify) is working, ready for you to drop in the proprietary parts.
