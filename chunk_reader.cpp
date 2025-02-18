//
// Created by Antonia Januszewicz on 2/17/25.
//
#ifndef chunk_reader

#define chunk_reader
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

class ChunkReader {
private:
    std::ifstream file;
    size_t chunkSize;
    std::string currentNumber;
    bool endOfFile;
    std::string filename;
    bool lineEnded;  // Track if the last chunk ended with a carriage return

public:
    ChunkReader(const std::string& fname, size_t size)
            : chunkSize(size), endOfFile(false), filename(fname), lineEnded(false) {
        file.open(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Unable to open file: " + filename);
        }
    }

    // Move constructor
    ChunkReader(ChunkReader&& other) noexcept
            : chunkSize(other.chunkSize),
              currentNumber(std::move(other.currentNumber)),
              endOfFile(other.endOfFile),
              filename(std::move(other.filename)),
              lineEnded(other.lineEnded) {
        file = std::move(other.file);
    }

    // Delete copy constructor and assignment operator
    ChunkReader(const ChunkReader&) = delete;
    ChunkReader& operator=(const ChunkReader&) = delete;

    ~ChunkReader() {
        if (file.is_open()) {
            file.close();
        }
    }

    bool hasNext() const {
        return !endOfFile;
    }

    const std::string& getFilename() const {
        return filename;
    }

    // Return value indicates if chunk was read successfully
    // lineEnded parameter indicates if a carriage return was encountered
    bool nextChunk(std::vector<double>& chunk, bool& hadCarriageReturn) {
        if (endOfFile) {
            hadCarriageReturn = false;
            return false;
        }

        chunk.clear();
        size_t currentCount = 0;
        char c;
        bool chunkHasData = false;
        hadCarriageReturn = false;

        while (currentCount < chunkSize && file.get(c)) {
            chunkHasData = true;

            if (c == ',') {
                if (!currentNumber.empty()) {
                    try {
                        chunk.push_back(std::stof(currentNumber));
                        currentCount++;
                        currentNumber.clear();
                    } catch (const std::invalid_argument& e) {
                        std::cerr << "Warning: Invalid float value found: " << currentNumber << std::endl;
                        currentNumber.clear();
                    }
                }
            }
            else if (c == '\n' || c == '\r') {
                if (!currentNumber.empty()) {
                    try {
                        chunk.push_back(std::stof(currentNumber));
                        currentCount++;
                        currentNumber.clear();
                    } catch (const std::invalid_argument& e) {
                        std::cerr << "Warning: Invalid float value found: " << currentNumber << std::endl;
                        currentNumber.clear();
                    }
                }

                // Handle \r\n line endings
                if (c == '\r') {
                    file.get(c);
                    if (c != '\n') {
                        file.putback(c);
                    }
                }

                hadCarriageReturn = true;

                // If we have any data, pad and return the chunk
                if (currentCount > 0) {
                    while (currentCount < chunkSize) {
                        chunk.push_back(0.0f);
                        currentCount++;
                    }
                    return true;
                }
            }
            else if (std::isspace(c)) {
                continue;
            }
            else {
                currentNumber += c;
            }

            // If we've filled a chunk, return it
            if (currentCount == chunkSize) {
                return true;
            }
        }

        // Handle last number if we have one
        if (!currentNumber.empty()) {
            try {
                chunk.push_back(std::stof(currentNumber));
                currentCount++;
                currentNumber.clear();
            } catch (const std::invalid_argument& e) {
                std::cerr << "Warning: Invalid float value found: " << currentNumber << std::endl;
            }
        }

        // If we got here, we've reached the end of the file
        endOfFile = true;

        // If we have any data in the final chunk, pad and return it
        if (currentCount > 0) {
            while (currentCount < chunkSize) {
                chunk.push_back(0.0f);
                currentCount++;
            }
            return true;
        }

        // No more data
        return false;
    }
};


#endif