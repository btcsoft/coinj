package org.bitcoinj.params;

import org.bitcoinj.core.Sha256Hash;
import org.coinj.api.CheckpointsContainer;

import java.util.HashMap;

/**
 * Date: 4/17/15
 * Time: 8:31 PM
 *
 * @author Mikhail Kulikov
 */
public class CheckpointsMapContainer implements CheckpointsContainer {

    private final HashMap<Integer, Sha256Hash> container;

    CheckpointsMapContainer(HashMap<Integer, Sha256Hash> container) {
        this.container = container;
    }

    @Override
    public void put(int key, String value) {
        container.put(key, new Sha256Hash(value));
    }

}
