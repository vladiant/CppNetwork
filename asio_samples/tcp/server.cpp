#include <asio.hpp>
#include <iostream>
#include <string>

using asio::ip::tcp;

const unsigned short BANKING_PORT = 50013;

int main() {
  try {
    asio::io_context io_context;

    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), BANKING_PORT));

    for (;;) {
      tcp::socket socket(io_context);
      acceptor.accept(socket);

      std::array<char, 128> buf{};
      asio::error_code error;
      size_t len = socket.read_some(asio::buffer(buf), error);

      if (error) throw asio::system_error(error);  // Some other error.

      std::cout.write(buf.data(), len);

      std::string message = "Response\n";

      asio::error_code ignored_error;
      asio::write(socket, asio::buffer(message), ignored_error);
    }
  } catch (asio::system_error& e) {
    std::cerr << "TCP exception: " << e.what() << std::endl;
  }

  return EXIT_SUCCESS;
}