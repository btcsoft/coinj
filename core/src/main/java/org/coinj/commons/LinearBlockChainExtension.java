/**
 * Copyright 2015 BitTechCenter Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.coinj.commons;

import org.bitcoinj.core.*;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.coinj.api.BlockChainExtension;
import org.coinj.api.CoinDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * Date: 4/30/15
 * Time: 9:11 PM
 *
 * @author Mikhail Kulikov
 */
public class LinearBlockChainExtension implements BlockChainExtension {

    private static final Logger log = LoggerFactory.getLogger(LinearBlockChainExtension.class);
    private static final String[] EMPTY_STRING_ARRAY = new String[]{};

    protected final AbstractBlockChain blockChain;
    private final long testnetDiffDate;

    public LinearBlockChainExtension(AbstractBlockChain blockChain, long testnetDiffDate) {
        this.blockChain = blockChain;
        this.testnetDiffDate = testnetDiffDate;
    }

    @Override
    public void verifyBlockAddition(Block block, List<Sha256Hash> filteredTxHashList, @Nullable Map<Sha256Hash, Transaction> filteredTxn) {}

    @Override
    public final void verifyDifficultyTransitions(final StoredBlock prevBlock, final Block added, final NetworkParameters params) {
        final Block prev = prevBlock.getHeader();

        // Is this supposed to be a difficulty transition point?
        final int heightPrev = prevBlock.getHeight();
        if ((heightPrev + 1) % params.getInterval(prev, heightPrev) != 0) {

            // TODO: Refactor this hack after 0.5 is released and we stop supporting deserialization compatibility.
            // This should be a method of the NetworkParameters, which should in turn be using singletons and a subclass
            // for each network type. Then each network can define its own difficulty transition rules.
            final CoinDefinition.StandardNetworkId standardNetworkId = params.getStandardNetworkId();
            if ((CoinDefinition.TEST_NETWORK_STANDARD.equals(standardNetworkId) || checkAdditionalTestNets(standardNetworkId)) && (added.getTimeSeconds() * 1000L) > testnetDiffDate) {
                checkTestnetDifficulty(prevBlock, added, blockChain.getBlockStore(), params);
                return;
            }

            // No ... so check the difficulty didn't actually change.
            if (added.getDifficultyTarget() != prev.getDifficultyTarget()) {
                throw new VerificationException("Unexpected change in difficulty at height " + heightPrev +
                        ": " + Long.toHexString(added.getDifficultyTarget()) + " vs " +
                        Long.toHexString(prev.getDifficultyTarget()));
            }

            return;
        }

        // We need to find a block far back in the chain. It's OK that this is expensive because it only occurs every
        // two weeks after the initial block chain download.
        long now = System.currentTimeMillis();
        StoredBlock cursor = prevBlock;
        try {
            final BlockStore blockStore = blockChain.getBlockStore();
            for (int i = 0; i < backTill(params, prevBlock, added); i++) {
                cursor = cursor.getPrev(blockStore);
                if (cursor == null) {
                    // This should never happen. If it does, it means we are following an incorrect or busted chain.
                    throw new VerificationException("Difficulty transition point but we did not find a way back to the genesis block.");
                }
            }
        } catch (BlockStoreException bsEx) {
            throw new VerificationException("Block store exception during descending chain walk", bsEx);
        }
        long elapsed = System.currentTimeMillis() - now;
        if (elapsed > 50)
            log.info("Difficulty transition traversal took {} msec", elapsed);

        if (cursorHook(cursor))
            return;

        Block blockIntervalAgo = cursor.getHeader();
        int timespan = (int) (prev.getTimeSeconds() - blockIntervalAgo.getTimeSeconds());
        // Limit the adjustment step.
        final int targetTimespan = params.getTargetTimespan(added, heightPrev + 1);
        if (timespan < targetTimespan / 4)
            timespan = targetTimespan / 4;
        if (timespan > targetTimespan * 4)
            timespan = targetTimespan * 4;

        BigInteger newTarget = Utils.decodeCompactBits(prev.getDifficultyTarget());
        newTarget = newTarget.multiply(BigInteger.valueOf(timespan));
        newTarget = newTarget.divide(BigInteger.valueOf(targetTimespan));

        if (newTarget.compareTo(params.getMaxTarget()) > 0) {
            log.info("Difficulty hit proof of work limit: {}", newTarget.toString(16));
            newTarget = params.getMaxTarget();
        }

        int accuracyBytes = (int) (added.getDifficultyTarget() >>> 24) - 3;
        long receivedTargetCompact = added.getDifficultyTarget();

        // The calculated difficulty is to a higher precision than received, so reduce here.
        BigInteger mask = BigInteger.valueOf(0xFFFFFFL).shiftLeft(accuracyBytes * 8);
        newTarget = newTarget.and(mask);
        long newTargetCompact = Utils.encodeCompactBits(newTarget);

        if (newTargetCompact != receivedTargetCompact)
            throw new VerificationException("Network provided difficulty bits do not match what was calculated: " +
                    newTargetCompact + " vs " + receivedTargetCompact);
    }

    @Override
    public void onBlockAddition(StoredBlock block) {}

    protected boolean cursorHook(StoredBlock cursor) {
        return false;
    }

    protected String[] additionalStandardNetworkIdsForTestNets() {
        return EMPTY_STRING_ARRAY;
    }

    protected int backTill(NetworkParameters network, StoredBlock prevBlock, Block added) {
        return network.getInterval(added, prevBlock.getHeight() + 1) - 1;
    }

    private boolean checkAdditionalTestNets(CoinDefinition.StandardNetworkId networkId) {
        if (networkId == null)
            return false;

        for (final String id : additionalStandardNetworkIdsForTestNets()) {
            if (id.equals(networkId.str())) {
                return true;
            }
        }
        return false;
    }

    private static void checkTestnetDifficulty(final StoredBlock prevBlock, final Block added, final BlockStore blockStore, final NetworkParameters params) {
        // After 15th February 2012 the rules on the testnet change to avoid people running up the difficulty
        // and then leaving, making it too hard to mine a block. On non-difficulty transition points, easy
        // blocks are allowed if there has been a span of 20 minutes without one.
        final long timeDelta = added.getTimeSeconds() - prevBlock.getHeader().getTimeSeconds();
        // There is an integer underflow bug in bitcoin-qt that means mindiff blocks are accepted when time
        // goes backwards.
        if (timeDelta >= 0 && timeDelta <= params.getTargetSpacing(prevBlock.getHeader(), prevBlock.getHeight()) * 2) {
            // Walk backwards until we find a block that doesn't have the easiest proof of work, then check
            // that difficulty is equal to that one.
            StoredBlock cursor = prevBlock;
            final BigInteger maxTarget = params.getMaxTarget();
            try {
                while (!cursor.getHeader().getHashAsString().equals(params.getGenesisBlockHash()) &&
                        cursor.getHeight() % params.getInterval(cursor.getHeader(), cursor.getHeight()) != 0 &&
                        Utils.decodeCompactBits(cursor.getHeader().getDifficultyTarget()).equals(maxTarget)) {
                    final StoredBlock backup = cursor;
                    cursor = cursor.getPrev(blockStore);
                    if (cursor == null) {
                        throw new VerificationException("Unable to get down the test chain: block " +
                                (backup.getHeader().getHashAsString()) + " doesn't have previous block");
                    }
                }
            } catch (BlockStoreException bsEx) {
                throw new VerificationException("Block store exception during descending chain walk, testnet version", bsEx);
            }

            final BigInteger cursorTarget = Utils.decodeCompactBits(cursor.getHeader().getDifficultyTarget());
            if (isBadDifficultyTarget(cursorTarget, maxTarget)) {
                throw new VerificationException("Block " + (cursor.getHeader().getHashAsString()) + " have bad difficulty target: " + cursorTarget.toString());
            }
            BigInteger newTarget = Utils.decodeCompactBits(added.getDifficultyTarget());
            if (isBadDifficultyTarget(newTarget, maxTarget)) {
                throw new VerificationException("Added block have bad difficulty target: " + cursorTarget.toString());
            }

            if (!cursorTarget.equals(newTarget))
                throw new VerificationException("Testnet block transition that is not allowed: " +
                        Long.toHexString(cursor.getHeader().getDifficultyTarget()) + " vs " +
                        Long.toHexString(added.getDifficultyTarget()));
        }
    }

    private static boolean isBadDifficultyTarget(BigInteger target, BigInteger maxTarget) {
        return target.signum() <= 0 || target.compareTo(maxTarget) > 0;
    }

}
