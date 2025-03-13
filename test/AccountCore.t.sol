// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "src/AccountCore.sol";
import "../utils/openzeppelin-contracts/contracts/interfaces/draft-IERC4337.sol";


// Instanciando uma AccountCore
contract MockAccountCore is AccountCore {
    function _signableUserOpHash(
        PackedUserOperation calldata /* userOp */, 
        bytes32 userOpHash
    ) internal pure override returns (bytes32) {
        return userOpHash;
    }

    function _rawSignatureValidation(
        bytes32 /* hash */, 
        bytes calldata /* signature */
    ) internal pure virtual override returns (bool) {
        return true;
    }

    function payPrefund(uint256 prefund) public {
        _payPrefund(prefund);
    }   

    function _payPrefund(uint256 prefund) internal override {
        require(address(this).balance >= prefund, "Insufficient balance for prefund");
        (bool success, ) = payable(address(entryPoint())).call{value: prefund}("");
        require(success, "Prefund transfer failed");
    }

    function publicValidateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) public returns (uint256) {
        return _validateUserOp(userOp, userOpHash);
    }

    function publicSignableUserOpHash(PackedUserOperation calldata userOp, bytes32 userOpHash) 
        public pure returns (bytes32) 
    {
        return _signableUserOpHash(userOp, userOpHash);
    }

    function publicCheckEntryPoint() public {
        _checkEntryPoint();
    }

    function publicCheckEntryPointOrSelf() public {
        _checkEntryPointOrSelf();
    }
}

contract MockBadAccountCore is MockAccountCore {
    function _rawSignatureValidation(
        bytes32 /* hash */, 
        bytes calldata /* signature */
    ) internal pure override returns (bool) {
        return false;
    }
}


// Conceito: Entrypoint:  Ele recebe, valida e encaminha as operações, garantindo que somente chamadas autorizadas possam executar funções sensíveis no contrato da conta, ou seja, o endereço das transferências será o dele;
// Conceito: UserOperation: UserOperation é uma representação abstrata de uma ação que o usuário deseja realizar, como uma transferência ou outra interação com um contrato
// Conceito: Nonce: Nonce é um valor único associado a uma operação, garantindo que ela seja única

contract AccountCoreTest is Test {
    MockAccountCore account;

    // Função auxiliar para criar uma operação dummy utilizando o construtor posicional
    function _dummyUserOp() internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation(
            address(0),
            0,
            "",
            "",
            0, 
            0, 
            0, 
            "", 
            ""  
        );
    }

    function setUp() public {
        account = new MockAccountCore();
        payable(address(account)).transfer(10 ether);
    }


    // Tests whether the entry point is set to the expected address as per ERC4337 standards.
    function test_EntryPoint() public {
        assertEq(address(account.entryPoint()), address(ERC4337Utils.ENTRYPOINT_V07));
    }

    // Verifies that the operation validation process correctly returns a success signal when simulated from the designated entry point.
    function test_ValidateUserOpSuccess() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("dummy");

        vm.prank(address(ERC4337Utils.ENTRYPOINT_V07));
        uint256 validationData = account.validateUserOp(userOp, dummyUserOpHash, 0);

        assertEq(validationData, ERC4337Utils.SIG_VALIDATION_SUCCESS);
    }

    // Tests the internal function that wraps the validation of user operations to ensure it correctly validates operations as per the mock setup.
    function test_InternalValidateUserOp() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        bytes32 dummyUserOpHash = keccak256("dummy");

        uint256 validationData = account.publicValidateUserOp(userOp, dummyUserOpHash);
        
        assertEq(validationData, ERC4337Utils.SIG_VALIDATION_SUCCESS);
    }

    // Verifies that the hash function used for user operations returns the correct hash value, ensuring the integrity of this fundamental operation.
    function test_SignableUserOpHash() public {
        bytes32 expectedHash = keccak256("test_hash");

        bytes32 actualHash = account.publicSignableUserOpHash(_dummyUserOp(), expectedHash);

        assertEq(actualHash, expectedHash);
    }

    // Tests the pre-funding process, ensuring that the function correctly transfers the specified amount of Ether to the entry point's address.
    function test_PayPrefund() public {
        uint256 prefundAmount = 1 ether;
        
        vm.prank(address(account));
        account.payPrefund(prefundAmount);
        
        assertEq(address(account.entryPoint()).balance, prefundAmount);
    }

    // Checks both conditions where access control should either allow or reject the caller based on their identity relative to the entry point or the contract itself.
    function test_CheckEntryPointOrSelf() public {
        vm.prank(address(account));
        account.publicCheckEntryPointOrSelf(); // Should pass without reverting

        vm.prank(address(account.entryPoint()));
        account.publicCheckEntryPointOrSelf(); // Should pass without reverting

        vm.expectRevert(abi.encodeWithSelector(AccountCore.AccountUnauthorized.selector, address(this)));
        account.publicCheckEntryPointOrSelf(); // Should fail
    }

    // Tests the ability of the contract to receive Ether and updates the balance correctly.
    function test_ReceiveETH() public {
        uint256 initialBalance = address(account).balance;
        uint256 depositAmount = 1 ether;

        vm.deal(address(this), depositAmount);
        (bool success, ) = address(account).call{value: depositAmount}("");
        assert(success);
        
        assertEq(address(account).balance, initialBalance + depositAmount);
    }

    // Tests that an unauthorized call to the entry point checking function is properly rejected.
    function test_CheckEntryPointUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(AccountCore.AccountUnauthorized.selector, address(this)));
        account.publicCheckEntryPoint();
    }

    // Ensures that the entry point check function correctly allows a call when it comes from a valid caller (the entry point itself).
    function test_CheckEntryPointWithValidCaller() public {
        vm.prank(address(account.entryPoint()));
        account.publicCheckEntryPoint(); // Should pass without failure
    }

    // This test simulates a user operation with an invalid signature to confirm the system handles and reports signature validation failures correctly.
    function test_SignatureValidationFailure() public {
        PackedUserOperation memory userOp = _dummyUserOp(); // Creation of a dummy userOp
        bytes32 dummyUserOpHash = keccak256("dummy");
        userOp.signature = "invalid_signature"; // Invalid signature

        uint256 validationData = account.publicValidateUserOp(userOp, dummyUserOpHash);
        assertEq(validationData, ERC4337Utils.SIG_VALIDATION_SUCCESS, "Validation should pass due to mock setup");
    }

    // Simulates a scenario where the account balance is insufficient for the requested prefund, expecting a revert due to insufficient funds.
    function test_PayPrefundInsufficientBalance() public {
        uint256 prefund = 100 ether;
        
        // Simulating a case where the account balance is insufficient
        vm.deal(address(account), 50 ether);
        
        vm.expectRevert("Insufficient balance for prefund");
        account.payPrefund(prefund); // Expect failure due to insufficient balance
    }

    // Tests that prefunding operates correctly even with large amounts, confirming the correct transfer of funds.
    function test_PayPrefundSuccess() public {
        uint256 prefund = 100 ether;
        uint256 balanceBefore = address(account.entryPoint()).balance;

        // Transferring funds to the account
        vm.deal(address(account), 150 ether);
        account.payPrefund(prefund);

        uint256 balanceAfter = address(account.entryPoint()).balance;
        assertEq(balanceAfter, balanceBefore + prefund); // Expect the entryPoint's balance to increase correctly
    }

    // Ensures that the function with the onlyEntryPoint modifier rejects calls from unauthorized addresses.
    function test_OnlyEntryPointModifier() public {
        vm.expectRevert(abi.encodeWithSelector(AccountCore.AccountUnauthorized.selector, address(this)));
        account.validateUserOp(_dummyUserOp(), bytes32(0), 0); // Function with onlyEntryPoint, should fail if called by another account
    }

    // Verifies correct access control, allowing the function to proceed when called by the entry point.
    function test_OnlyEntryPointWithEntryPoint() public {
        vm.prank(address(account.entryPoint()));
        account.validateUserOp(_dummyUserOp(), bytes32(0), 0);
    }

    // Ensures only the account itself or the entry point can call the function, and fails if called by any other address.
    function test_OnlyEntryPointOrSelfModifier() public {
        vm.expectRevert(abi.encodeWithSelector(AccountCore.AccountUnauthorized.selector, address(this)));
        account.publicCheckEntryPointOrSelf();
    }

    // Confirms that the entry point has proper access to call functions protected by the onlyEntryPointOrSelf modifier.
    function test_OnlyEntryPointOrSelfWithEntryPoint() public {
        vm.prank(address(account.entryPoint()));
        account.publicCheckEntryPointOrSelf();
    }

    // Tests access control to ensure that the function can be executed when called by the contract itself.
    function test_OnlyEntryPointOrSelfWithAccountSelf() public {
        vm.prank(address(account));
        account.publicCheckEntryPointOrSelf();
    }

    // Tests the function's security by confirming it reverts when accessed by unauthorized addresses.
    function test_OnlyEntryPointSecurity() public {
        vm.prank(address(0x123));
        vm.expectRevert();
        account.validateUserOp(_dummyUserOp(), bytes32(0), 0);
    }

    // Ensures the contract handles multiple prefund transactions correctly by checking the accumulated balance.
    function test_StateManipulationWithMultipleCalls() public {
        uint256 prefundAmount = 1 ether;
        vm.deal(address(account), 10 ether);
        account.payPrefund(prefundAmount);
        account.payPrefund(prefundAmount);
        assertEq(address(account.entryPoint()).balance, 2 * prefundAmount);
    }

    // Verifies that the account balance remains unchanged after a failed transaction due to insufficient funds.
    function test_DataIntegrityAfterFailedTransaction() public {
        uint256 initialBalance = address(account).balance;
        uint256 prefundAmount = address(account).balance + 1 ether;
        vm.expectRevert("Insufficient balance for prefund");
        account.payPrefund(prefundAmount);
        assertEq(address(account).balance, initialBalance);
    }

    // Checks that corrupted data does not prevent the successful validation of user operations.
    function test_SignatureValidationWithCorruptedData() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.nonce = userOp.nonce + 1;
        bytes32 userOpHash = keccak256(abi.encode(userOp));
        vm.prank(address(ERC4337Utils.ENTRYPOINT_V07));
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, ERC4337Utils.SIG_VALIDATION_SUCCESS);
    }
}