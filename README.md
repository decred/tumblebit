TumbleBit implementation for Decred
===================================

TumbleBit package implements the TumbleBit protocol for the Decred
cryptocurrency. There are two executable binaries installed:

  * `tumblebit` -- the tumblebit service
  * `dcrtumble` -- the tumblebit client

`tumblebit` implements a gRPC service for clients and requires a
connection to the dcrwallet service to handle transaction and wallet
services for the tumbler itself.

When a decred user Alice informs another user Bob that she wants to
make a payment in an out-of-band manner (from the blockchain PoV), Bob
is required to obtain a set of puzzle promises from the tumbler.  He
does so by issuing a sequence of RPC calls:

  * SetupEscrow to indicate a desire to receive a payment and obtain a
    signed but not published 2-of-2 escrow transaction;

  * GetPuzzlePromises to obtain puzzle promises;

  * FinalizeEscrow to finish the escrow process and acknowledge
    validity of provided puzzle promises.

When any of these puzzles are solved (by the tumbler), Bob has a way
to finalize a cash-out transaction redeeming escrowed funds.

During this puzzle-promise protocol the following transactions are
prepared:

  * a 2-of-2 escrow created by the tumbler that requires signatures
    from both tumbler and Bob to be redeemed *or* a signature from the
    tumbler to be able to issue a refund after a locktime;

  * a refund transaction created by the tumbler that will need to be
    posted after the locktime in case escrow won't be redeemed;

  * a redeeming transaction (a.k.a. the cash-out tx) prepared by Bob
    that he will post on to the blockchain once it obtains the puzzle
    solution from Alice which would reveal the tumbler's signature of
    the redeeming tx hash needed to complete the redeeming script and
    redeem escrowed funds.

Once escrow process is finished (FinalizeEscrow has been called), Bob
may blind one of the received puzzles and offer it to Alice via an
out-of-band communication channel.

Once Alice receives the blinded puzzle (later referred as the puzzle)
corresponding to a particular epoch (block height) she can construct
a series of puzzles of her own to test tumbler's ability to solve
them. Once Alice verifies that tumbler is capable of providing valid
solutions for puzzles, it commits to an offer transaction that escrows
funds that can be redeemed by posting a redeeming transaction that
contains preimages for a series of keys opening solutions to the
blinded puzzle.

Alice must call the following RPC calls in sequence:

  * GetSolutionPromises to obtain solutions promises for puzzles of
    her choice which is a mix of actual ("real") puzzles and test
    ("fake") ones;

  * ValidateSolutions to reveal test ("fake") puzzles and obtain proof
    that tumbler can indeed solve these puzzles;

  * PaymentOffer to signify a commitment to pay for the puzzle
    solution.

During this puzzle-solver protocol Alice creates an offer transaction
which is an escrow contract that can be redeemed by the tumbler if it
offers valid preimages for RIPEMD-160 hashes contained in the offer
transaction.  Or alternatively it's refunded by Alice after a
locktime.

These preimages are solutions for blindings of the same puzzle and
once solution is applied and puzzle is unblinded it opens up to a
solution of a puzzle provided by Bob.

Now that Alice has paid the tumbler, she can communicate the solution
back to Bob via an out-of-band comm channel so that Bob can use it to
reveal the signature on the cash-out transaction and redeem funds
escrowed by the tumbler by posting the finalized redeeming tx
concluding the payment from Alice to Bob via the TumbleBit service.


TODO
====

1. Refund transactions must be stored in a database and issued
   whenever escrows haven't been redeemed at the end of an epoch.

2. Finish dcrtumble's command interface.  Post intermediate results as
   JSON encoded objects so that they can be fed back to dcrtumble at a
   later point.

3. Post all solution transactions at the same time for a single epoch
   to not let observers correlate different payment phases.

4. Implement Anonymous voucher system to let payer handle transaction
   fees for the payee.
