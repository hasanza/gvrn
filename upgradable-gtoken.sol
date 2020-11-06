pragma solidity ^0.5.16;
pragma experimental ABIEncoderV2;

contract GVRN {
    string public constant symbol = "GVRN";
    string public constant decimals = 18;
    string public constant totalSupply = 10000000e18;
    //allowances to others
    //allowances[allower][allowee] returns qty allowed
    mapping (address => mapping(address => uint96)) internal allowances;
    //token balance for each address
    mapping (address => uint96) internal balances;
    //delegate addresses for an address
    mapping (address => address) internal delegates;
    //Marks the No. of votes in a given block. e.g. how much votes did an addres have at a given block
    struct Checkpoint {
        uint32 fromBlock;
        uint96 votes;
    }
    //mappint of vote checkpoints for an address, by index
    //checkpoints[address][index] returns a checkpoint object with blockNum and no. of votes for that address in said block
    mapping (address => mapping (uint32 => Checkpoint)) public checkpoints;
    // No. of checkpoints (vote count in given block) for an address
    mapping (address => uint32) public numCheckpoints;
    //typehashes for structs; typehash is the keccak256 hash of the encodeType of the type of the data being encoded
    //The EIP712 (allows for message to be shown in signing prompts - previously only a bytestring was shown) typehash for contract's domain
    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
    //typehash for the delegation struct used by the contract
    bytes32 public constant DELEGATION_TYPEHASH = keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)");
    //nonces to keep track of signing signatures
    //nonces[address] returns the no. of nonces for an address
    mapping(address => uint) public nonces;
    //-----events
    //when an address changes its delegate
    event DelegateChanged (address indexed delegator, address indexed fromDelegate, address indexed toDelegate);
    //when a delegate's vote balance (i.e. GVRN token balance which is equal to the amount held by the delegator) changes
    event DelegateVotesChanged(address indexed delegate, uint previousBalance, uint newBalance);
    //ERC20 token transfer event
    event Transfer(address indexed from, address indexed to, uint256 amount);
    //ERC20 token approve event
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    //constructor function. 
    //grants an address all the GVRN voting token supply. Typecasts to uint96 since 96 bits enough for totalSupply
    function initialize(address account) public {
        balances[account] = uint96(totalSupply);
        emit Transfer(address(0), account, totalSupply);
    }

    //returns no. of tokens allowed by an address to another to be spent
    function allowance(address account, address spender) external view returns (uint) {
        return allowances[account][spender];
    }

    //uses typecasting and limitchecking to safely approve amounts for an address 
    function approve(address spender, uint rawAmount) external returns (bool) {
        uint96 amount;
        if (rawAmount == uint(-1)) {
            amount = uint96(-1);
        } else {
            amount = safe96(rawAmount, "Gvrn::approve: amount exceeds 96bits");
        }
        allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender)[spender] = amount;
        return true;
    }

    //returns GVRN voting token balance for an account
    function balanceOf(address account) external view returns (uint) {
        return balances[account];
    }

    //transfer amount to destination address.
    function transfer(address dst, uint rawAmount) external returns (bool) {
        //check if received amount is within the 96 bit limit (tokensupply occupies max 96bits)
        uint96 amount = safe96(rawAmount, "Comp::transfer: amount exceeds 96 bits");
        _transferTokens(msg.sender, dst, amount);
        return true;
    }

    function transferFrom(address src, address dst, uint rawAmount) external returns (bool) {
        address spender = msg.sender;
        //how much the src address i.e. the allower has allowed the spender to spend
        uint96 spenderAllowance = allowances[src][spender];
        uint amount = safe96(rawAmount, "Gvrn::approve: amount exceeds 96 bits");
        //check of spender is actually the allower and allowance is not 0.
        if(spender != src && spenderAllowance!= uint96(-1)) {
            uint96 newAllowance = sub96(spenderAllowance, amount, "Comp::transferFrom: transfer amount exceeds spender allowance");
            allowances[src][spender] = newAllowance;

            emit Approval(src, spender, newAllowance);
        }

        _transferTokens(src, dst, amount);
        return true;
    } 

    //delegates votes from msg.sender to delegatee
    function delegate(address delegatee) public {
        return _delegate(msg.sender, delegatee);
    }

    //delegate votes from signer to delegatee. Enables offline participation
    //v byte is the recoverybyte that lets us recover the signer
    function delegateBySig(address delegatee, uint nonce, uint expiry, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), getChainId(), address(this)));
        bytes32 structHash = keccak256(abi.encode(DELEGATION_TYPEHASH, delegatee, nonce, expiry));
        //digest = hash of the prefix + domainSparator hash and struct hash.
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        //digest is the message object that was signed by the signer
        address signatory = ecrecover(digest, v, r, s);
        require(signatory != address(0), "Comp::delegateBySig: invalid signature");
        require(nonce == nonces[signatory]++, "Comp::delegateBySig: invalid nonce");
        require(now <= expiry, "Comp::delegateBySig: signature expired");
        //after verifications and checks, make address receied the delegatee of the signer
        return _delegate(signatory, delegatee);
    }

    //returns current gvrn token balance for an account in the current/ latest block
    function getCurrentVotes(address account) external view returns (uint96){
        uint32 nCheckpoints = numCheckpoints[account];
        //check if checkpoints exist, if yes, return the votes in the nCheckpoint object in the latest mined block
        return nCheckpoints > 0 ? checkpoints[account][nCheckpoints - 1].votes : 0;
    }

    //get no. of votes for an address at a past block
    function getPriorVotes(address account, uint blockNumber) public view returns (uint96) {
        require (blockNumber < block.number, "Comp::getPriorVotes: not yet determined");

        uint32 nCheckpoints = numCheckpoints[accounts];
        if (nCheckpoints == 0) {
            return 0;
        }

        if (checkpoints[account][nCheckpoints - 1].fromBlock <= blockNumber) {
            return checkpoints[accounts][nCheckpoints - 1].votes;
        }

        if (checkpoints[account][0].fromBlock > blockNumber) {
            return 0;
        }

        uint32 lower = 0;
        uint32 upper = nCheckpoints - 1;
        while (upper > lower) {
            uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow
            Checkpoint memory cp = checkpoints[account][center];
            if (cp.fromBlock == blockNumber) {
                return cp.votes;
            } else if (cp.fromBlock < blockNumber) {
                lower = center;
            } else {
                upper = center - 1;
            }
        }
        return checkpoints[account][lower].votes;
    }

    function _delegate(address delegator, address delegatee) internal {
       //the current delegate for the delegator
        address currentDelegate = delegates[delegator];
        //the no. of gvrn voting tokens the delegator has
        uint96 delegatorBalance = balances[delegator];
        //make the received address the new delegatee
        delegates[delegator] = delegatee;

        emit DelegateChanged(delegator, currentDelegate, delegatee);
        //adjust the delegate mapping
        _moveDelegates(currentDelegate, delegatee, delegatorBalance);
    }

        //srcRep is the prev delegate and dstRep is the new one
        function _moveDelegates(address srcRep, address dstRep, uint96 amount) internal {
            //check if srcRep and dstRep are not the same and amount being delegated (i.e. held by delegator )is not 0
        if (srcRep != dstRep && amount > 0) {
            //if srcTep is not the 0 address, update the checkpoint records to reflect the tokens as being held by the new delegatee
            if (srcRep != address(0)) {
                uint32 srcRepNum = numCheckpoints[srcRep];
                //srcRep's votes in the latest confirmed block (so latest index - 1)
                uint96 srcRepOld = srcRepNum > 0 ? checkpoints[srcRep][srcRepNum - 1].votes : 0;
                //decrease the amount of votes held by the old delegatee by the amount which was given to it by the current delegator
                uint96 srcRepNew = sub96(srcRepOld, amount, "Comp::_moveVotes: vote amount underflows");
                //write new checkpoint reflecting the votes held by the old delegate currently in the latest block
                _writeCheckpoint(srcRep, srcRepNum, srcRepOld, srcRepNew);
            }

            if (dstRep != address(0)) {
                //no of checkpoint objects for the new delegate
                uint32 dstRepNum = numCheckpoints[dstRep];
                //the no. of votes/ Gvrn tokens held by ht new delegate at the last confirmed block
                uint96 dstRepOld = dstRepNum > 0 ? checkpoints[dstRep][dstRepNum - 1].votes : 0;
                //the no. of votes held by the new delegate is now increased by the amount held by the delegator
                uint96 dstRepNew = add96(dstRepOld, amount, "Comp::_moveVotes: vote amount overflows");
                //write new checkpoint reflecting the votes held by the new delegate currently in the latest block
                _writeCheckpoint(dstRep, dstRepNum, dstRepOld, dstRepNew);
            }
        }
    }

    //if the delegatee is a first timer, create a new checkpoint for it in the latest block. 
    //Otherwise, adjust the votecount in the blocks where the checkpoints exist for this delegatee 

    function _writeCheckpoint(address delegatee, uint32 nCheckpoints, uint96 oldVotes, uint96 newVotes) internal {
        //get the current block number
      uint32 blockNumber = safe32(block.number, "Comp::_writeCheckpoint: block number exceeds 32 bits");
        //if the delegatee already has checkpoint(s) and the latest checkpoint is from the current block,
      if (nCheckpoints > 0 && checkpoints[delegatee][nCheckpoints - 1].fromBlock == blockNumber) {
          //change the no. of votes in the checkpoint to reflect the delegation changes
          checkpoints[delegatee][nCheckpoints - 1].votes = newVotes;
      } else {
          //otherwise if the given delegatee is a first time delegatee, create a new checkpoint object with the received no. of votes 
          checkpoints[delegatee][nCheckpoints] = Checkpoint(blockNumber, newVotes);
          //increase the checkpoint count for the delegatee
          numCheckpoints[delegatee] = nCheckpoints + 1;
      }

      emit DelegateVotesChanged(delegatee, oldVotes, newVotes);
    }

    //the below are all utility functions 

    function safe32(uint n, string memory errorMessage) internal pure returns (uint32) {
        require(n < 2**32, errorMessage);
        return uint32(n);
    }

    function safe96(uint n, string memory errorMessage) internal pure returns (uint96) {
        require(n < 2**96, errorMessage);
        return uint96(n);
    }

    function add96(uint96 a, uint96 b, string memory errorMessage) internal pure returns (uint96) {
        uint96 c = a + b;
        require(c >= a, errorMessage);
        return c;
    }

    function sub96(uint96 a, uint96 b, string memory errorMessage) internal pure returns (uint96) {
        require(b <= a, errorMessage);
        return a - b;
    }

    function getChainId() internal pure returns (uint) {
        uint256 chainId;
        assembly { chainId := chainid() }
        return chainId;
    }

}
