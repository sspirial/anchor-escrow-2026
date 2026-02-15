/**
 * PoC: Fund Lock via Token Program Mismatch
 * 
 * This test demonstrates that WITHOUT the fix, a malicious taker could
 * permanently lock escrowed tokens by passing the wrong token program.
 * 
 * WITH the fix (has_one = token_program), the attack is blocked.
 * 
 * Run: npx tsx --test --test-reporter=spec tests/poc_fund_lock.ts
 * (Or via: npm test — which runs all tests/*.ts)
 */
import { before, describe, test } from "node:test";
import assert from "node:assert";
import * as programClient from "../dist/escrow-client";
import { connect, Connection, TOKEN_EXTENSIONS_PROGRAM } from "solana-kite";
import { type KeyPairSigner, type Address, address } from "@solana/kit";
import { createTestOffer, getRandomBigInt, ONE_SOL } from "./escrow.test-helpers";

// Legacy SPL Token Program ID
const LEGACY_TOKEN_PROGRAM = address("TokenkegQEcnVcFkvkK8vJto9P536Vj68nMaximum6R");

describe("PoC: Fund Lock via Token Program Mismatch", () => {
  let connection: Connection;
  let alice: KeyPairSigner;  // Maker (victim)
  let bob: KeyPairSigner;    // Taker (attacker)
  let tokenMintA: Address;
  let tokenMintB: Address;
  let aliceTokenAccountA: Address;
  let bobTokenAccountB: Address;
  let aliceTokenAccountB: Address;
  let bobTokenAccountA: Address;

  const tokenDecimals = 9;
  const TOKEN = 10n ** BigInt(tokenDecimals);

  before(async () => {
    connection = await connect();
    const [user, aliceWallet, bobWallet] = await connection.createWallets(3, { airdropAmount: ONE_SOL });
    alice = aliceWallet;
    bob = bobWallet;

    // Create mints using Token Extensions (Token-2022) — the default for this project
    tokenMintA = await connection.createTokenMint({
      mintAuthority: user,
      decimals: tokenDecimals,
      name: "Token A",
      symbol: "TKA",
      uri: "https://example.com/a",
    });
    tokenMintB = await connection.createTokenMint({
      mintAuthority: user,
      decimals: tokenDecimals,
      name: "Token B",
      symbol: "TKB",
      uri: "https://example.com/b",
    });

    // Fund wallets
    aliceTokenAccountA = await connection.createTokenAccount(alice, tokenMintA);
    await connection.mintTokens(tokenMintA, user, aliceTokenAccountA, 100n * TOKEN);

    bobTokenAccountB = await connection.createTokenAccount(bob, tokenMintB);
    await connection.mintTokens(tokenMintB, user, bobTokenAccountB, 100n * TOKEN);

    aliceTokenAccountB = await connection.createTokenAccount(alice, tokenMintB);
    bobTokenAccountA = await connection.createTokenAccount(bob, tokenMintA);
  });

  test("Attack: Taker passes Legacy Token Program instead of Token-2022 → blocked by has_one = token_program", async () => {
    // Step 1: Alice creates offer using Token-2022 (the project default)
    const { offer, vault, offerId } = await createTestOffer({
      connection,
      maker: alice,
      tokenMintA,
      tokenMintB,
      makerTokenAccountA: aliceTokenAccountA,
      tokenAOfferedAmount: 10n * TOKEN,
      tokenBWantedAmount: 5n * TOKEN,
    });

    // Verify vault holds the tokens
    const vaultBalance = await connection.getTokenBalance(vault);
    assert.equal(vaultBalance, 10n * TOKEN, "Vault should hold 10 Token A");

    // Step 2: Bob attempts take_offer with LEGACY Token Program (mismatch attack)
    // 
    // WITHOUT the fix: The vault would derive to a different ATA (Legacy-derived),
    // which is empty. The program would transfer 0 tokens, close the offer PDA,
    // and Alice's real tokens would be orphaned forever.
    //
    // WITH the fix (has_one = token_program): The offer's stored token_program
    // is Token-2022, but Bob passes Legacy. The has_one constraint catches the
    // mismatch and rejects the transaction.

    try {
      // Derive the "wrong" vault using Legacy Token Program
      // (This would be a different address than the real vault)
      const wrongVault = await connection.getTokenAccountAddress(offer, tokenMintA, true);

      const takeOfferIx = await programClient.getTakeOfferInstructionAsync({
        taker: bob,
        maker: alice.address,
        tokenMintA,
        tokenMintB,
        takerTokenAccountA: bobTokenAccountA,
        takerTokenAccountB: bobTokenAccountB,
        makerTokenAccountB: aliceTokenAccountB,
        offer,
        vault: wrongVault,
        tokenProgram: LEGACY_TOKEN_PROGRAM,  // ATTACK: wrong program
      });

      await connection.sendTransactionFromInstructions({
        feePayer: bob,
        instructions: [takeOfferIx],
      });

      assert.fail(
        "VULNERABILITY: Attack transaction succeeded! " +
        "The offer was closed with a mismatched token program. " +
        "Alice's tokens in the real vault are now permanently locked."
      );
    } catch (error: any) {
      // Expected: Transaction should fail due to has_one = token_program constraint
      const errorMessage = error.message || String(error);
      console.log(`    ✅ Attack blocked: ${errorMessage.substring(0, 100)}`);
      
      // The error should indicate a constraint violation
      // (has_one = token_program mismatch)
      assert.ok(
        errorMessage.includes("ConstraintHasOne") || 
        errorMessage.includes("has one constraint was violated") ||
        errorMessage.includes("constraint"),
        `Expected constraint error, got: ${errorMessage.substring(0, 200)}`
      );
    }

    // Step 3: Verify Alice's funds are safe
    const vaultBalanceAfter = await connection.getTokenBalance(vault);
    assert.equal(vaultBalanceAfter, 10n * TOKEN, "Vault should still hold 10 Token A (funds safe)");

    // Offer should still exist (attack was blocked)
    const offerAccount = await connection.getAccount(offer);
    assert.ok(offerAccount, "Offer PDA should still exist");

    console.log("    ✅ Alice's funds are safe. Offer still active.");
  });

  test("Normal flow: Take offer with correct token program succeeds", async () => {
    // Ensure the fix doesn't break normal operations
    const { offer, vault, offerId } = await createTestOffer({
      connection,
      maker: alice,
      tokenMintA,
      tokenMintB,
      makerTokenAccountA: aliceTokenAccountA,
      tokenAOfferedAmount: 5n * TOKEN,
      tokenBWantedAmount: 3n * TOKEN,
    });

    const takeOfferIx = await programClient.getTakeOfferInstructionAsync({
      taker: bob,
      maker: alice.address,
      tokenMintA,
      tokenMintB,
      takerTokenAccountA: bobTokenAccountA,
      takerTokenAccountB: bobTokenAccountB,
      makerTokenAccountB: aliceTokenAccountB,
      offer,
      vault,
      tokenProgram: TOKEN_EXTENSIONS_PROGRAM,  // Correct program
    });

    await connection.sendTransactionFromInstructions({
      feePayer: bob,
      instructions: [takeOfferIx],
    });

    console.log("    ✅ Normal take_offer with correct token program succeeds.");
  });
});
