// Your First C++ Program

#include <iostream>
#include <arpa/inet.h>

std::string replace(std::string input, std::string from, std::string to)
{
  std::cout << from << std::endl;
  std::cout << to << std::endl;
  size_t pos = 0;
  pos = input.find(from.c_str(), pos);
  while (pos != std::string::npos)
  {
    input.replace(pos, sizeof(to.c_str()), to.c_str());
    pos += sizeof(to.c_str());
    pos = input.find(from.c_str(), pos);
  }
  return input;
}

int main()
{

  std::cout < < < < std::endl;
  return 0;
}