#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <PayloadLayer.h>
#include <Packet.h>
#include <PcapFileDevice.h>

#include <stdint.h>
#include <stdio.h>

#include <iostream>
#include <string>

#include "lib/argparse.hpp"


uint64_t process_pcap_file(pcpp::PcapFileReaderDevice &reader, FILE *outfile, bool binary) {
  uint64_t packet_count = 0;

  pcpp::RawPacket rawPacket;
  while (reader.getNextPacket(rawPacket)) {
    pcpp::Packet parsedPacket(&rawPacket);
    if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
      packet_count++;

      auto timestamp = rawPacket.getPacketTimeStamp();
      //uint64_t usec_time = (timestamp.tv_sec * 1000000ull) + timestamp.tv_usec;
      uint64_t usec_time = (timestamp.tv_sec * 1000000ull) + (timestamp.tv_nsec / 1000);

      auto ip_layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

      auto src_ip = ip_layer->getSrcIpAddress();
      auto dst_ip = ip_layer->getDstIpAddress();

      uint8_t protocol = ip_layer->getIPv4Header()->protocol;

      uint16_t src_port = 0;
      uint16_t dst_port = 0;

      if (ip_layer->getNextLayer()) {
        if (parsedPacket.isPacketOfType(pcpp::TCP)) {
          auto tcp_layer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
          src_port = be16toh(tcp_layer->getTcpHeader()->portSrc);
          dst_port = be16toh(tcp_layer->getTcpHeader()->portDst);
        } else if (parsedPacket.isPacketOfType(pcpp::UDP)) {
          auto udp_layer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
          src_port = be16toh(udp_layer->getUdpHeader()->portSrc);
          dst_port = be16toh(udp_layer->getUdpHeader()->portDst);
        } else if (parsedPacket.isPacketOfType(pcpp::GenericPayload)) {
          auto layer = parsedPacket.getLayerOfType<pcpp::PayloadLayer>();
          // the layer below is a UDP or TCP layer that has not be recognized
          if ((protocol == 17 && layer->getPayloadLen() == 8) ||
              (protocol == 6 && layer->getPayloadLen() >= 20 && layer->getPayloadLen() <= 60)) {
            uint16_t *payload = (uint16_t *) layer->getPayload();
            src_port = be16toh(payload[0]);
            dst_port = be16toh(payload[1]);
          }
        }
      }

      if (binary) {
        usec_time = htobe64(usec_time);
        fwrite(&usec_time, sizeof(uint64_t), 1, outfile);

        uint32_t src_ip_int = htobe32(src_ip.toInt());
        fwrite(&src_ip_int, sizeof(uint32_t), 1, outfile);

        uint32_t dst_ip_int = htobe32(dst_ip.toInt());
        fwrite(&dst_ip_int, sizeof(uint32_t), 1, outfile);

        //fwrite(&protocol, sizeof(uint8_t), 1, outfile);

        src_port = htobe16(src_port);
        //fwrite(&src_port, sizeof(uint16_t), 1, outfile);

        dst_port = htobe16(dst_port);
        //fwrite(&dst_port, sizeof(uint16_t), 1, outfile);
      } else {
        fprintf(outfile, "%lu %s %s \n", usec_time, src_ip.toString().c_str(), dst_ip.toString().c_str());
      }
    }
  }

  return packet_count;
}

int main(int argc, char **argv) {
  // setup commandline arguments
  argparse::ArgumentParser argparse(argv[0]);
  argparse.add_argument("input")
      .help("input pcap file(s)")
      .remaining();

  argparse.add_argument("-o", "--output")
      .help("output file, if not provided STDOUT is used")
      .nargs(1);

  argparse.add_argument("-b")
      .help("binary output")
      .default_value(false)
      .implicit_value(true);

  // parse the arguments
  try {
    argparse.parse_args(argc, argv);
    if (argparse.get<std::vector<std::string>>("input").empty()) {
      throw "No input.";
    }
  } catch (const std::exception &err) {
    std::cout << err.what() << std::endl;
    std::cout << argparse;
    return EXIT_FAILURE;
  }

  FILE *outfile = stdout;

  // open a file if provided
  if (auto output = argparse.present<std::string>("-o")) {
    outfile = fopen(output->c_str(), "wb+");
    if (outfile == NULL) {
      std::cerr << "Failed to open output file." << std::endl;
      return EXIT_FAILURE;
    }
  }

  uint64_t total_packet_count = 0;

  auto files = argparse.get<std::vector<std::string>>("input");

  for (std::string file : files) {
    // load the pcap file
    pcpp::PcapFileReaderDevice reader(file.c_str());
    if (!reader.open()) {
      return EXIT_FAILURE;
    }

    uint64_t packet_count = process_pcap_file(reader, outfile, argparse.get<bool>("-b"));
    total_packet_count += packet_count;

    reader.close();

    std::cerr << file << ": " << packet_count << " packets" << std::endl;
  }

  if (outfile != stdout) {
    fclose(outfile);
  }

  std::cerr << "Parsed " << total_packet_count << " packets." << std::endl;

  return EXIT_SUCCESS;
}
