package org.coinj.commons;

import com.google.common.collect.ImmutableList;
import org.bitcoinj.core.InventoryItem;
import org.coinj.api.PeerExtension;

/**
 * Date: 5/16/15
 * Time: 4:55 AM
 *
 * @author Mikhail Kulikov
 */
public abstract class AbstractPeerExtension implements PeerExtension {

    public static abstract class AbstractInventoryAccumulator implements InventoryAccumulator {

        private final ImmutableList.Builder<InventoryItem> builder = ImmutableList.builder();

        @Override
        public boolean addItem(InventoryItem item) {
            if (!isItemSupported(item))
                return false;

            builder.add(item);
            return true;
        }

        public ImmutableList<InventoryItem> getItemsList() {
            return builder.build();
        }

        protected abstract boolean isItemSupported(InventoryItem item);

    }

}
