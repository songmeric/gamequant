#include "Engine.h"
#include "ShutdownUtils.h"
#include <filesystem>
#include <chrono>
#include <vector>
#include <deque>  // For discoverySuccessFlags_
#include <thread> // For std::this_thread::get_id()
#include <memory> // For std::make_unique
#include <spdlog/spdlog/wait.hpp>
#include <iostream>
#include "DropcopyHandler.h"
#include "OutputFileAction.h"

Engine::Engine(const std::string dropcopy_directory, const std::vector<std::string>& dirs_to_watch, unsigned num_workers, unsigned queue_capacity)
    : dc_(dropcopy_directory),
    directories_to_watch_(dirs_to_watch),
    num_worker_threads_(num_workers),
    queue_capacity_(queue_capacity),
    queue_(queue_capacity),
    log_(PME_GET_LOGGER("Engine"))
{
    PME_LOG_INFO(log_, "Engine initialized. Dirs: " << directories_to_watch_.size() << ", Workers: " << num_worker_threads_ << ", Queue Cap: " << queue_capacity_ << ".");
}

void Engine::stop() {
    PME_LOG_INFO(log_, "Engine shutting down. Joining threads.");
    shutdown::g_shutdownRequested = true; //true, std::memory_order_release);
    if(OutputFileWriter::write(outputMap_, "/lxhome/songjoon/pme/output"))
    {
        PME_LOG_INFO(log_, "Successfully written output csv");
    }
    queue_.wakeAll();
    
    for (auto& thread : discoveryThreads_) {
        if (thread.joinable()) {
            thread.join();
            PME_LOG_INFO(log_, "Discovery threads joined.");
        }
        else {
            PME_LOG_INFO(log_, "Not joinable Discovery thread, skipping.");
        }
    }
    
    for (auto& thread : workerThreads_) {
        if (thread.joinable()) {
            thread.join();
            PME_LOG_INFO(log_, "Worker threads joined.");
        }
        else {
            PME_LOG_INFO(log_, "Not joinable Worker thread, skipping.");
        }
    }

    PME_LOG_INFO(log_, "Engine shutdown complete.");
}

void Engine::run() {
    PME_LOG_INFO(log_, "Engine starting...");
    
    for (size_t i = 0; i < directories_to_watch_.size(); ++i) {
        const auto& dir_path = directories_to_watch_[i];
        if (dir_path.empty()) {
            PME_LOG_WARN(log_, "Empty directory path provided, skipping.");
            continue;
        }
        PME_LOG_INFO(log_, "Creating discovery thread for directory: " << dir_path);
        discoveryThreads_.emplace_back(&Engine::discoveryInstanceLoop, this, dir_path, std::ref(queue_), std::ref(log_));
    }
    
    // Start Worker Threads
    workerThreads_.reserve(num_worker_threads_);
    for (unsigned i = 0; i < num_worker_threads_; ++i) {
        PME_LOG_INFO(log_, "Creating worker thread #" << (i + 1));
        workerThreads_.emplace_back(&Engine::workerMain, this);
    }
    
    PME_LOG_INFO(log_, "Engine running with " << discoveryThreads_.size() << " discovery thread(s) and " << workerThreads_.size() << " worker thread(s).");
    int sig = sp::app::wait();
    
    PME_LOG_FATAL(log_, "Shutdown signal: " << sig << " received, Engine run loop ending.");
    stop();
}

void Engine::discoveryInstanceLoop(std::string dir, FileQueue& q, px::Log* engine_logger) {
    Discovery discovery_instance(dir,q,engine_logger);
    
    PME_LOG_INFO(log_, "Discovery loop started for directory: " << discovery_instance.getDirectory());
    discovery_instance.run();
    PME_LOG_INFO(log_, "Discovery loop finished for directory: " << discovery_instance.getDirectory());
}

void Engine::workerMain() {
    PME_LOG_INFO(log_, "Worker thread (ID: " << std::this_thread::get_id() << ") started.");
    
    PacketProcessor packet_processor(dc_.getMmapRef()); // Each worker thread gets its own instance
    
    std::string file_path;
    while (!shutdown::requested()) {
        bool popped_item = queue_.pop(file_path); // Blocking pop
        
        if (shutdown::requested() && !popped_item) { // Check if shutdown was reason for pop failing
            PME_LOG_INFO(log_, "Worker (Thread ID: " << std::this_thread::get_id() << ") breaking main loop due to shutdown signal and empty queue after pop attempt.");
            break;
        }
        
        if (shutdown::requested() && popped_item) {
            PME_LOG_INFO(log_, "Worker (Thread ID: " << std::this_thread::get_id() << ") popped an item but shutdown was requested. Will process then check shutdown again.");
        }
        
        if (popped_item) {
            bool process_this_file = false;
            {
                std::lock_guard<std::mutex> guard(processed_files_mutex_);
                if (processed_files_.find(file_path) == processed_files_.end()) {
                    processed_files_.insert(file_path);
                    process_this_file = true;
                } else {
                    PME_LOG_INFO(log_, "File '" << file_path << "' already processed or currently being processed by another worker. Skipping. Thread ID: " << std::this_thread::get_id());
                }
            }
            
            if (process_this_file) {
                PME_LOG_DEBUG(log_, "Worker (Thread ID: " << std::this_thread::get_id() << ") processing file: " << file_path);
                std::unordered_map<uint64_t, std::vector<ParsedPacketInfo>> tMap = packet_processor.processFile(file_path); // Use PacketProcessor instance
                outputMap_.insert(tMap.begin(), tMap.end());
            }
        } else if (!shutdown::requested()) { // Popped item is false, but not due to shutdown
            PME_LOG_TRACE(log_, "Worker pop returned false but not shutting down, yielding. Thread ID: " << std::this_thread::get_id());
            std::this_thread::yield();
        }
    }
    
    PME_LOG_INFO(log_, "Worker (Thread ID: " << std::this_thread::get_id() << ") entering shutdown drain loop.");
    while (queue_.pop(file_path)) {
        bool process_this_file = false;
        {
            std::lock_guard<std::mutex> guard(processed_files_mutex_);
            if (processed_files_.find(file_path) == processed_files_.end()) {
                processed_files_.insert(file_path);
                process_this_file = true;
            } else {
                PME_LOG_INFO(log_, "File '" << file_path << "' (drain) already processed. Skipping. Thread ID: " << std::this_thread::get_id());
            }
        }
        
        if (process_this_file) {
            PME_LOG_DEBUG(log_, "Worker (Thread ID: " << std::this_thread::get_id() << ", shutdown drain) processing remaining file: " << file_path);
            std::unordered_map<uint64_t, std::vector<ParsedPacketInfo>> tMap = packet_processor.processFile(file_path); // Use PacketProcessor instance
            outputMap_.insert(tMap.begin(), tMap.end());
        }
    }
    
    PME_LOG_INFO(log_, "Worker loop finished. Thread ID: " << std::this_thread::get_id());
}
