## References
- Secureum "ETH 101"
- https://docs.soliditylang.org/en/v0.8.27/
- https://solidity-by-example.org/
- https://www.smartcontract.engineer/courses
- DASP / OWASP Top 10
- Remedy Vulnerability Wiki
- Johnny Time Course
- [CTFs & Audit Platforms](https://github.com/Anugrahsr/Awesome-web3-Security)
- Solodit Reports
- Audit Wizard Tool

### Environment & Tools
- VSCode
  - Solidity + Solidity Visual Developer Extensions 
  - Call graph generation
  - `@audit` Comments
 
- Hardhat Projects
  - `mkdir [project_folder]` + `npx hardhat init`
  - `code [project_folder]`
  - `npx hardhat compile` -> Compile Contracts
  - `npx hardhat run [deploy_script]` -> Run/Deploy Contract Scripts
  - `npx hardhat test [test_script]` -> Execute Tests
  - `npx hardhat node` -> Deploy a Local Blockchain
 
- MetaMask
  - Switch to Local Network via `31337` Chain ID
  - Add HardHat Node Accounts via Secret Keys
 
### EVM Components
An ETH node spawns a EVM instance everytime there is a transaction to a contract that contains data. The components of the EVM are:
- Global Variables (available throughout the transaction)
  - Block
  - TX
  - Message Information
  - Gas Sent
- Persistent Variables (stored on the blockchain)
  - Contract Code
  - Contract Storage/State
  - Machine State (Balances, Nonces)
- Volatile Variables (wiped after transaction)
  - Stack
  - Program Counter
  - Runtime Gas
 
A transaction that triggers the EVM is a "call", they can be internal or external depending on the type of the function being called
- Internal
  - The function was internal/private accessed inside the current or derived contract
- External
  - The function is an external/public inside another contract
  - Normal Call -> Executes with contract B code/storage, and global variables of the caller contract
  - Delegated Call -> Executes with contract A code/storage, and global variables of the previous caller (EOA/Contract)
    
### Solidity Basics
```Solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Variables {

  // Accessibility & Storage
  uint256 public test;          // Accessible from any contract
  uint256 private test;         // Accessible only from this contract
  uint256 internal test;        // Accessible from this and derived contracts
  uint256 public constant test; // Public + Not Modifiable (save gas cost)
  uint256 memory myArray = numbers;                // Variables using "memory" are stored in the cache
  function func(){string public chk = "Helo!";}    // Variables inside functions are stored in the cache

  // Integers
  [int/uint][8-256] MyInteger = 84600;
    // The min/max value of an integer can be found via "type(uint[8-256]).min/max"
    // The uint "x" overflows when adding "y = type(uint[8-256]).max + 1 - x"
    // The uint "x" underflows when adding "y = type(uint[8-256]).min - 1 - x" 

  // Arrays, Mappings
  uint256[] numbers;
  mapping(address user => uint balance) public balances;
    // Mappings are not iterable, always in storage, and cannot be returned by a function
    // Arrays can be stored in memory and are iterable
    // Iterable Mappings are possible via libraries -> https://solidity-by-example.org/app/iterable-mapping/

  // Addresses, Payables
  address ContractAddr = 0xa83114A443dA1CecEFC50368531cACE9F37fCCcb;
  address payable ETHWallet = 0xa83114A443dA1adcEFC50368556cACE9F37fCCdf;
  uint256 balance = address(this).balance
    // A payable address has ".transfer/.send" methods, and will add received ETH to its ".balance"
    // A user wallet is always payable, a contract address can be made payable by adding a receiver/fallback
    // "address(this)" fetches the current contract's address

  // Payable Contract
  receive() external payable {}
  fallback() external {
    emit Received(msg.sender, msg.value, "Fallback was triggered");
  }

  // Functions
  function [name](<args>) [external|internal|private|public| [pure|view|payable] [modifier] [returns (<ret types>)]{}
    // External - Accessible only externally
    // Internal - Accessible only from current or derived contracts
    // Private - Accessible only from the current contract
    // Public - Accessible from everywhere

    // Pure - Disallow storage read/write
    // View - Disallow storage write
    // Payable - Allow access to "msg.value" to handle ETH

  // Constructors
  address payable owner;
  constructor() { owner = payable(msg.sender); }
     // Executed once the contract is created, they can have arguments that get sent at creation time
     // It's possible to have separated constructors, by putting them in derived contracts without any arguments

  // ABI Calling
  function ABICall(address remote) public {
    (bool success, bytes memory data) = remote.call{value: [val], gas: [gas]}(abi.encodeWithSignature("ExternalFunc(arg_types)", arg1, arg2, ...));

  // Interface Calling 
  interface IRemote { [external_func_prototype]; }
  contract Exploit {
    IRemote remote;
    constructor(address _adr) {
        remote = IRemote(_adr);
    }
    function func() external { remote.external_func{gas: [gas], value: [wei]}(arg1, arg2, ...); }
  }

  // Blockchain, Message Variables
  block.number                                 // Tee current block number
  block.timestamp                              // The current time of the block
  blockhash(uint blockNumber) returns bytes32  // Hash of a block number (max previous 256)
  msg.data                                     // Complete Message Data (bytes256)
  msg.sender                                   // Address of the current call sender
  msg.value                                    // Number of wei sent with the message
  tx.origin                                    // Address of the original call-chain sender

  // Modifiers, Error Handling
  require(bool expression, "Error");
  modifier onlySeller() {
    require(msg.sender == seller, "Error Message");
    _;
  }
    // Enforce authorization labels on functions
    // Handle errors via "require()", when failing it will revert the transaction/state
```
As a simple example, here is a smart contract that implements an ETH wallet in which only the owner can withdraw money from
```Solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0

contract ETHWallet {
  // Constructor for owner authorization check
  address payable public owner;
  constructor() { owner = payable(msg.sender); }

  // Making the Contract payable
  receive() external payable {}
  fallback() external {
    emit Received(msg.sender, msg.value, "Fallback was triggered");
  }

  // A modifier to enforce owner-authorization checks
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  // Anybody can view the balance
  function checkBalance() public view returns(uint256) { return address(this).balance; }

  // Only the owner can withdraw money
  function witdhraw(uint256 amount) public payable onlyOwner { payable(msg.sender).transfer(amount); }
}
``` 

### ERC20 Tokens
ERC20 Tokens are smart contracts implementing divisible and liquidable coins, which means you can trade them with centralized/de-centralized exchange protocols, for example Uniswap V2. 

Because the tokens are fungible, they must all be created under the same standard, otherwise the exchange protocol would not be able to interact with them on the same footing, the most used standard is OpenZeppelin `ERC20.sol` available here:
- `@openzeppelin/contracts/token/ERC20/ERC20.sol`

The repository also contains ERC20 Extensions which can be studied to increase the usage possibilities of the token, like setting an ownership or changing how the tokens can be minted/burned. Every token has a fixed decimal point, for example when it equals to 6 it will convert the uint value `94560000` to `94.56` during a transfer between addresses. Similar requirements like having a name and symbol are implemented in the ERC20 standard.

Here is an example of a ERC20 Token
```Solidity
//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Import the ERC20 Standard
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Create a derived contract for your token
contract HackersToken is ERC20 {
  address public owner;

  // Call the ERC20 Constructor with a name and symbol
  constructor() ERC20("Hackers Token", "HTK") {
    owner = msg.sender;
  }

  // Create an external mint function using the built-in "_mint", only for the contract owner
  function mint(address _to, uint _amount) external {
    require(msg.sender == owner, "Not Owner!");
    _mint(_to, _amount);
  }
}
```

### ERC721 Tokens
ERC721 Tokens are representations of an asset on the blockchain, they have a unique ID and are not tradable, however they can be sold/purchased via ERC20 Tokens making them ideal for creating an asset collection. The most used standard is available at:
- `@openzeppelin/contracts/token/ERC721/ERC721.sol`

### Security Pitfalls
- Do not assume storage variables to be invisible, they are on the blockchain!
- Do not use `blockhash` and `block.timestamp` as randomness sources
- Do not use `tx.origin` for addresses authorization checks
- Do not produce uint overflows, they revert the state in checked mode, and overflow variables in unchecked mode 
- Do not perform important state updates after `transfer()`, `call()`, or `send()`, don't assume they succeed and check the return value of `send()`
- Do not use controllable state variables as loop index bounds
- Do not rely on `address(this).balance` for authorization, a contract cannot refuse `selfdestruct` transfers
