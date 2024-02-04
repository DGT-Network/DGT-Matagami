pragma solidity ^0.8.0;

contract dgtkeys {
  mapping (uint => uint) intmap;

  event Set(uint key, uint value);

  function set(uint key, uint value) public {
    intmap[key] = value;
    emit Set(key, value);
  }

  function inc(uint key) public {
    intmap[key] = intmap[key] + 1;
  }

  function dec(uint key) public {
    require(intmap[key] > 0, "Value INTMAP[key] should be more then 0");
    intmap[key] = intmap[key] - 1;
  }

  function get(uint key) public view returns (uint retVal) {
    return intmap[key];
  }
}
