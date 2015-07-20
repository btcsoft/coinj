/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoinj.tools;

import com.google.common.base.Charsets;
import org.bitcoinj.core.*;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;

import javax.annotation.Nullable;
import java.io.*;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Date;
import java.util.TreeMap;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * Downloads and verifies a full chain from your local peer, emitting checkpoints at each difficulty transition period
 * to a file which is then signed with your key.
 */
public class BuildCheckpoints {

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.init();


        final Integer networkIdIndex = findArgsCommand(args, "networkId");
        final NetworkParameters params;
        final File plainCheckpointsFile;
        final File textualCheckpointsFile;
        if (networkIdIndex != null) {
            final String networkId = args[networkIdIndex + 1];
            params = NetworkParameters.fromID(networkId);
            plainCheckpointsFile = new File("checkpoints_" + networkId);
            textualCheckpointsFile = new File("checkpoints_" + networkId + ".txt");
        } else {
            params = MainNetParams.get();
            plainCheckpointsFile = new File("checkpoints");
            textualCheckpointsFile = new File("checkpoints.txt");
        }
        checkNotNull(params, "params is NULL from args " + Arrays.toString(args));

        // Sorted map of block height to StoredBlock object.
        final TreeMap<Integer, StoredBlock> checkpoints = new TreeMap<>();

        // Configure bitcoinj to fetch only headers, not save them to disk, connect to a local fully synced/validated
        // node and to save block headers that are on interval boundaries, as long as they are <1 month old.
        final BlockStore store = new MemoryBlockStore(params);
        final BlockChain chain = new BlockChain(params, store);

        final PeerGroup peerGroup = new PeerGroup(params, chain);

        if (findArgsCommand(args, "useDiscovery") != null) {
            peerGroup.addPeerDiscovery(new DnsDiscovery(params));
            peerGroup.setUseLocalhostPeerWhenPossible(false);
        } else {
            peerGroup.addAddress(InetAddress.getLocalHost());
        }

        final long now = new Date().getTime() / 1000;

        final Integer fctIndex = findArgsCommand(args, "fastCatchupTimeSecs");
        final long fastCatchupTimeSecs = (fctIndex == null) ? now : Long.valueOf(args[fctIndex + 1]);

        peerGroup.setFastCatchupTimeSecs(fastCatchupTimeSecs);

        long al = fastCatchupTimeSecs - (86400 * params.getCoinDefinition().getCheckpointDaysBack());
        if (al <= params.getGenesisBlock().getTimeSeconds()) {
            al = now;
        }
        final long arbitraryLimit = al;

        chain.addListener(new AbstractBlockChainListener() {
            @Override
            public void notifyNewBestBlock(StoredBlock block) throws VerificationException {
                int height = block.getHeight();
                final Block header = block.getHeader();
                if (height % params.getCoinDefinition().getIntervalCheckpoints(header.cloneAsHeader(), height, params.getStandardNetworkId()) == 0
                        && header.getTimeSeconds() <= arbitraryLimit)
                {
                    System.out.println(String.format("Checkpointing block %s at height %d",
                            header.getHash(), block.getHeight()));
                    checkpoints.put(height, block);
                }
            }
        }, Threading.SAME_THREAD);

        peerGroup.startAsync();
        peerGroup.awaitRunning();
        peerGroup.downloadBlockChain();

        checkState(checkpoints.size() > 0);

        // Write checkpoint data out.
        writeBinaryCheckpoints(checkpoints, plainCheckpointsFile);
        writeTextualCheckpoints(checkpoints, textualCheckpointsFile);

        peerGroup.stopAsync();
        peerGroup.awaitTerminated();
        store.close();

        // Sanity check the created files.
        CheckCheckpoints.sanityCheck(plainCheckpointsFile, checkpoints, params);
        CheckCheckpoints.sanityCheck(textualCheckpointsFile, checkpoints, params);
    }

    @Nullable
    private static Integer findArgsCommand(String[] args, String command) {
        for (int i = 0; i < args.length; i++) {
            final String a = args[i];
            if (a.equalsIgnoreCase(command)) {
                return i;
            }
        }
        return null;
    }

    private static void writeBinaryCheckpoints(TreeMap<Integer, StoredBlock> checkpoints, File file) throws Exception {
        final FileOutputStream fileOutputStream = new FileOutputStream(file, false);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final DigestOutputStream digestOutputStream = new DigestOutputStream(fileOutputStream, digest);
        digestOutputStream.on(false);
        final DataOutputStream dataOutputStream = new DataOutputStream(digestOutputStream);
        dataOutputStream.writeBytes("CHECKPOINTS 1");
        dataOutputStream.writeInt(0);  // Number of signatures to read. Do this later.
        digestOutputStream.on(true);
        dataOutputStream.writeInt(checkpoints.size());
        ByteBuffer buffer = ByteBuffer.allocate(StoredBlock.COMPACT_SERIALIZED_SIZE);
        for (StoredBlock block : checkpoints.values()) {
            block.serializeCompact(buffer);
            dataOutputStream.write(buffer.array());
            buffer.position(0);
        }
        dataOutputStream.close();
        Sha256Hash checkpointsHash = new Sha256Hash(digest.digest());
        System.out.println("Hash of checkpoints data is " + checkpointsHash);
        digestOutputStream.close();
        fileOutputStream.close();
        System.out.println("Checkpoints written to '" + file.getCanonicalPath() + "'.");
    }

    private static void writeTextualCheckpoints(TreeMap<Integer, StoredBlock> checkpoints, File file) throws IOException {
        PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(file), Charsets.US_ASCII));
        writer.println("TXT CHECKPOINTS 1");
        writer.println("0"); // Number of signatures to read. Do this later.
        writer.println(checkpoints.size());
        ByteBuffer buffer = ByteBuffer.allocate(StoredBlock.COMPACT_SERIALIZED_SIZE);
        for (StoredBlock block : checkpoints.values()) {
            block.serializeCompact(buffer);
            writer.println(CheckpointManager.BASE64.encode(buffer.array()));
            buffer.position(0);
        }
        writer.close();
        System.out.println("Checkpoints written to '" + file.getCanonicalPath() + "'.");
    }

}
