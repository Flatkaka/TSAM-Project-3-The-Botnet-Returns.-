// Your First C++ Program

#include <iostream>
#include <arpa/inet.h>

std::string replace(std::string input, std::string from, std::string to)
{
  size_t pos = 0;
  pos = input.find(from.c_str(), pos);
  while (pos != std::string::npos)
  {
    std::string front = input.substr(0, pos) + to.c_str();
    std::string back = input.substr(pos + from.length());
    input = front + back;
    pos += to.length();
    pos = input.find(from.c_str(), pos);
  }
  return input;
}

int main()
{

  std::string msg = "hello, ba$by, trhi$$s is amzaing!!";
  std::string con = "connected,hilmard,12.564.22.432,1233;,120.22.12.33,32123;";
  std::cout << replace(msg, "$", "hilmar") << std::endl;
  std::cout << replace(con, ";,", "; ,") << std::endl;

  return 0;
}