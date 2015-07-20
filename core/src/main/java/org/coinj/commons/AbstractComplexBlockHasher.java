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

import javax.annotation.Nonnull;

/**
 * Date: 4/30/15
 * Time: 8:27 PM
 *
 * @author Mikhail Kulikov
 */
public abstract class AbstractComplexBlockHasher extends AbstractBlockHasher {

    private Sha256Hash pofHashCache;

    @Override
    public AbstractComplexBlockHasher copy() {
        final AbstractComplexBlockHasher copy = construct();
        enrichAbstractBlockExtension(copy);
        enrichAbstractComplexBlockExtension(copy);
        return copy;
    }

    protected final void enrichAbstractComplexBlockExtension(AbstractComplexBlockHasher blockExtension) {
        blockExtension.pofHashCache = this.pofHashCache;
    }

    @Override
    protected abstract AbstractComplexBlockHasher construct();

    @Override
    public void unCache() {
        super.unCache();
        pofHashCache = null;
    }

    @Override
    @Nonnull
    public Sha256Hash getProofOfWorkHash(Block block) {
        if (pofHashCache == null)
            initProofOfWorkHash(block);
        return pofHashCache;
    }

    @Override
    public void initProofOfWorkHash(Block block) {
        pofHashCache = calculatePofHash(block);
    }

    protected abstract Sha256Hash calculatePofHash(Block block);

}
