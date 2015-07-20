package org.bitcoinj.tools;

import org.bitcoinj.core.CheckpointManager;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.params.MainNetParams;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.TreeMap;

/**
 * Date: 5/4/15
 * Time: 6:17 AM
 *
 * @author Mikhail Kulikov
 */
public final class CheckCheckpoints {

    private static final NetworkParameters PARAMS = MainNetParams.get();
    private static final File PLAIN_CHECKPOINTS_FILE = new File("checkpoints");
    private static final File TEXTUAL_CHECKPOINTS_FILE = new File("checkpoints.txt");

    public static void main(String[] args) {
        try {
            final TreeMap<Integer, StoredBlock> checkpoints = new CheckpointManager(PARAMS, new FileInputStream(PLAIN_CHECKPOINTS_FILE)).getCheckpoints();
            sanityCheck(PLAIN_CHECKPOINTS_FILE, checkpoints, PARAMS);
            sanityCheck(TEXTUAL_CHECKPOINTS_FILE, checkpoints, PARAMS);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void sanityCheck(File file, TreeMap<Integer, StoredBlock> checkpoints, NetworkParameters params) throws IOException {
        CheckpointManager manager = new CheckpointManager(params, new FileInputStream(file));
        params.getCoinDefinition().checkpointsSanityCheck(manager, checkpoints, params.getStandardNetworkId());
    }


    private CheckCheckpoints() {}

}
