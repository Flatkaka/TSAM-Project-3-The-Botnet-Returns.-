// Your First C++ Program

#include <iostream>

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
  std::string msg = "hallo hashtag# her er lika stjarna #";

  // size_t hash_pos = 0;
  // hash_pos = msg.find("#", hash_pos);
  // while (hash_pos != std::string::npos)
  // {
  //   msg.replace(hash_pos, sizeof("##"), "##");
  //   hash_pos += sizeof("##");
  //   hash_pos = msg.find("#", hash_pos);
  // }

  // size_t star_pos = 0;
  // star_pos = msg.find("*", star_pos);
  // while (star_pos != std::string::npos)
  // {
  //   msg.replace(star_pos, sizeof("**"), "**");
  //   star_pos += sizeof("**");
  //   star_pos = msg.find("*", star_pos);
  // }
  // std::cout << msg << std::endl;

  msg = replace(msg, "#", "##");
  std::cout << msg << std::endl;
  return 0;
}