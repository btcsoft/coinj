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

import org.bitcoinj.core.Block;
import org.bitcoinj.core.Sha256Hash;
import org.coinj.api.BlockHasher;

import javax.annotation.Nonnull;

/**
 * Date: 4/30/15
 * Time: 7:49 PM
 *
 * @author Mikhail Kulikov
 */
public abstract class AbstractBlockHasher implements BlockHasher {

    private Sha256Hash hashCache;

    @Override
    @Nonnull
    public Sha256Hash getHash(Block block) {
        if (hashCache == null)
            initHash(block);
        return hashCache;
    }

    @Override
    public void initHash(Block block) {
        hashCache = calculateHash(block);
    }

    protected abstract Sha256Hash calculateHash(Block block);

    @Override
    public void unCache() {
        hashCache = null;
    }

    @Override
    public AbstractBlockHasher copy() {
        final AbstractBlockHasher copy = construct();
        enrichAbstractBlockExtension(copy);
        return copy;
    }

    protected final void enrichAbstractBlockExtension(AbstractBlockHasher blockExtension) {
        blockExtension.hashCache = this.hashCache;
    }

    protected abstract AbstractBlockHasher construct();

    @Override
    @Nonnull
    public Sha256Hash getProofOfWorkHash(Block block) {
        return getHash(block);
    }

    @Override
    public void initProofOfWorkHash(Block block) {
        initHash(block);
    }

}
