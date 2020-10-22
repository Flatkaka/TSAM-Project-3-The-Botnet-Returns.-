// Your First C++ Program

#include <iostream>
#include <arpa/inet.h>

std::string replace(std::string input, std::string from, std::string to)
{
  size_t pos = 0;
  pos = input.find(from.c_str(), pos);
  while (pos != std::string::npos)
  {
    std::string empty = "";
    input.replace(pos, 1, empty.c_str());
    input.insert(pos, to.c_str(), sizeof(to.c_str()));
    pos += sizeof(to.c_str());
    pos = input.find(from.c_str(), pos);
  }
  return input;
}

int main()
{

  std::string msg = "hello, ba$by, trhis is amzaing!!";
  std::cout << replace(msg, "$", "hilmar") << std::endl;

  return 0;
}